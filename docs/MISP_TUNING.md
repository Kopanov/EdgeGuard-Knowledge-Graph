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

## Where MISP runs (read this first)

**MISP is NOT in EdgeGuard's main `docker-compose.yml`.** EdgeGuard
treats MISP as the system of record; it's a separate, operator-managed
container that EdgeGuard talks to over HTTPS via `MISP_URL` /
`MISP_API_KEY`. The settings below apply to **your MISP container**,
wherever you run it — not to anything in EdgeGuard's compose file.

There are two MISP container images we've validated against. Where
the tuning files live depends on which one you use:

| Image | Base | PHP version | PHP config path inside container |
|---|---|---|---|
| `harvarditsecurity/misp:latest` | Ubuntu + Apache mod_php | PHP 8.x | `/etc/php/8.x/apache2/php.ini` (Apache SAPI) |
| `coolacid/misp-docker:latest` | Debian bullseye-slim + php-fpm | PHP 7.4 (older builds) / 8.x (newer) | `/etc/php/<ver>/fpm/conf.d/*.ini` (drop-in scan dir) |

**EdgeGuard's currently-deployed MISP is `harvarditsecurity/misp:latest`.**
The reference compose layout for the `coolacid` image (with mounted
`php-overrides.ini`) lives at
[`docs/sources/MISP/docker-compose.yml`](sources/MISP/docker-compose.yml)
+ [`docs/sources/MISP/php-overrides.ini`](sources/MISP/php-overrides.ini).
That reference compose is also a good template if you migrate from
`harvarditsecurity` to `coolacid` later.

### Which path to apply the TL;DR settings to

| If you use… | Apply PHP settings to… | Apply MySQL settings to… |
|---|---|---|
| `harvarditsecurity/misp:latest` (current) | edit `/etc/php/8.x/apache2/php.ini` inside the running container, OR mount a custom `*.ini` into `/etc/php/8.x/apache2/conf.d/zz-edgeguard.ini` (drop-in dir, scanned after php.ini). | Same as below — the image's own MariaDB / MySQL container; configure via `my.cnf` mount or the container's environment. |
| `coolacid/misp-docker:latest` | mount `php-overrides.ini` into `/etc/php/<ver>/fpm/conf.d/99-edgeguard.ini` per [`docs/sources/MISP/docker-compose.yml`](sources/MISP/docker-compose.yml). | the bundled `mysql:8.0` sidecar; configure via `my.cnf` mount. |

**Apache vs php-fpm — important.** The `harvarditsecurity` image runs
PHP via Apache mod_php, so the settings live under
`/etc/php/<ver>/apache2/`. The `coolacid` image runs PHP via php-fpm,
so the settings live under `/etc/php/<ver>/fpm/`. Editing the wrong
path silently does nothing. Always verify with:
```bash
docker compose exec misp php -i | grep memory_limit
```

### `mem_limit` on the docker compose service

Both images need the **container** memory ceiling raised in addition
to the PHP ceiling. The reference compose sets `mem_limit: 8g` on
both `misp` and `misp_db`. If your compose doesn't, the PHP process
will be killed by the kernel OOM-killer at the container limit even
though `memory_limit = 4096M` in php.ini would otherwise allow it.

```yaml
# docker-compose.yml — both services
services:
  misp:
    mem_limit: 8g
  misp_db:
    mem_limit: 8g
```

---

## Prerequisites — host capacity before applying

The TL;DR settings below assume a MISP host with **at least 8 GB
RAM** (PHP 4 GB + InnoDB 4 GB + OS/other ≈ 8 GB minimum). Applying
them on a 4 GB container will swap or OOM the host itself, which
is strictly worse than the un-tuned defaults.

| Host RAM | Suggested settings |
|---|---|
| < 4 GB | **Do not apply.** Use EdgeGuard env knobs to slow the writer (`EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD=10000`, batch=100, throttle=15s); plan a host upgrade. |
| 4 – 6 GB | `memory_limit = 2048M`, `innodb_buffer_pool_size = 2G`, leave the rest at TL;DR values. |
| 8 GB | TL;DR values exactly. |
| 16 GB+ | TL;DR values; raise `innodb_buffer_pool_size` to ~50% of RAM if the MISP DB is otherwise idle. |

Verify before applying:
```bash
docker compose exec misp free -h           # check container limit, not host
docker stats misp misp-db --no-stream      # current usage
```

---

## TL;DR — Apply these on the MISP container

> See **"Where MISP runs"** above for which path applies to your
> image (`harvarditsecurity` uses Apache `/etc/php/8.x/apache2/`;
> `coolacid` uses fpm `/etc/php/<ver>/fpm/conf.d/`). The values
> below are identical for both images.

### PHP — `php.ini` (Apache mod_php) or `conf.d/zz-edgeguard.ini` (php-fpm)

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

**For `harvarditsecurity/misp:latest`** — drop-in conf.d file (survives
container restart but not container rebuild; for permanence, mount via
docker-compose):
```bash
# In your MISP docker compose dir (NOT EdgeGuard's compose dir)
# Option A: edit php.ini directly inside the container
docker compose exec misp bash -c "cat >> /etc/php/8.2/apache2/php.ini <<'EOF'
memory_limit = 4096M
max_execution_time = 600
post_max_size = 256M
upload_max_filesize = 256M
max_input_vars = 50000
EOF"

# Option B (preferred): mount via docker-compose so it survives rebuild
# Add to your MISP docker-compose.yml under services.misp.volumes:
#   - ./misp-php-overrides.ini:/etc/php/8.2/apache2/conf.d/zz-edgeguard.ini:ro

docker compose restart misp misp_db
```

**For `coolacid/misp-docker:latest`** — use the reference compose +
`php-overrides.ini` already in this repo:
```bash
# Use the reference layout
cp docs/sources/MISP/docker-compose.yml /path/to/your/misp-deploy/
cp docs/sources/MISP/php-overrides.ini /path/to/your/misp-deploy/
cd /path/to/your/misp-deploy/
docker compose up -d
```

**Verify (both images):**
```bash
# PHP changes
docker compose exec misp php -i | grep -E 'memory_limit|max_execution_time|post_max_size'
# Should show: memory_limit => 4G => 4G  (or 8G if you bumped it)

# MySQL changes (service name varies: misp-db, misp_db_1, misp_db)
docker compose exec misp_db mysql -u root -p \
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
| `EDGEGUARD_MISP_BACKOFF_THRESHOLD` | `3` | Number of consecutive 5xx batch failures before EdgeGuard inserts an extended cooldown. **Valid range: 2–100.** Setting `1` would trigger the 5-min cooldown after a single failure (which `@retry_with_backoff` already handles internally), turning every transient 5xx into a multi-hour stall — values below 2 are silently clamped to the default 3 with a WARN. |
| `EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC` | `300.0` | Cooldown duration. 5 min is enough for MISP's PHP to recycle and MySQL to free transaction locks. |
| `EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS` | `true` | Cross-event dedup. **Leave on** — the adaptive scaling tier resolution depends on `existing_attrs_count` which is computed from the prefetch result. With prefetch off, the writer has no per-event size signal and falls back to the configured default batch/throttle for every event, which is exactly the un-adaptive behaviour PR-N4 tried to fix. Turning it off only makes sense if you have an external dedup layer (rare). |

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
| `edgeguard_misp_push_permanent_failure_total` | `source` | Each increment = one batch (default 500 attrs) lost after `@retry_with_backoff(max_retries=4)` exhausted. **Non-zero rate is the operator signal that backend is undersized.** Labelled by `source` only (PR-N4 round 2 dropped `event_id` to keep cardinality bounded — each MISP run creates a date-stamped event, which would generate one new time series per source per day). |
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

## Rollback — if a tuning change makes things worse

The settings here are field-tested for the documented workload, but
host hardware varies. If after applying you see the MISP container
swapping, the host OOMing, or the `edgeguard_misp_push_permanent_failure_total`
rate going up rather than down, roll back in this order:

1. **Halve `innodb_buffer_pool_size`** first (it's the biggest RAM
   consumer; 4G → 2G). Restart `misp-db`.
2. If still bad, **halve `memory_limit`** (4096M → 2048M). Restart `misp`.
3. If still bad, revert `php.ini` and `my.cnf` to the previous values
   from your container image (typically `memory_limit=512M`,
   `innodb_buffer_pool_size=128M`).
4. With the backend fully reverted, raise EdgeGuard's caution by
   setting:
   ```bash
   EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD=10000   # was 50000
   EDGEGUARD_MISP_PUSH_BATCH_SIZE=100           # was 500
   EDGEGUARD_MISP_BATCH_THROTTLE_SEC=15.0       # was 5.0
   ```
   This makes EdgeGuard work *with* the un-tuned MISP. It is slower
   (a 730d baseline that would have taken 4h now takes 8–10h) but
   correctness is preserved.
5. File a host-capacity ticket. The combination of a >150K-attribute
   single event and a sub-8GB MISP host is unsustainable for a
   production deployment.

The `edgeguard_misp_push_backoff_triggered_total` metric is the
single best signal that you're in this hole — if it's non-zero
after the tuning is applied, the tuning isn't sufficient for your
host.

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
