# MISP setup (reference)

EdgeGuard treats **MISP as the system of record** for collected intelligence. MISP is **not** vendored inside this repository — run it wherever you host Docker or a bare-metal MISP install.

## Typical Docker workflow

1. Use the official [MISP Docker](https://github.com/MISP/MISP) or your organisation’s image.
2. Expose the web UI (commonly **https://localhost:8443** or your hostname).
3. Create an **Org Admin** user and generate an **API key** for EdgeGuard (`MISP_API_KEY` in `.env`).

```bash
# Example only — paths depend on where YOU cloned MISP
cd /path/to/your/misp-docker
docker compose up -d
```

## EdgeGuard configuration

Point EdgeGuard at your instance:

```bash
MISP_URL=https://your-misp-host.example
MISP_API_KEY=...
```

See also: [SETUP_GUIDE.md](../../SETUP_GUIDE.md), [SECRETS_MANAGEMENT.md](../../SECRETS_MANAGEMENT.md), [MISP_SOURCES.md](../../MISP_SOURCES.md), and **[MISP_TUNING.md](../../MISP_TUNING.md) — required reading before a baseline run >50K attrs**.

## Image choice — `harvarditsecurity` vs `coolacid`

EdgeGuard validates against two MISP images. They differ only in PHP SAPI:

- **`harvarditsecurity/misp:latest`** — Apache mod_php; PHP config under `/etc/php/8.x/apache2/`. **Deployed for EdgeGuard.**
- **`coolacid/misp-docker:latest`** — php-fpm; PHP config under `/etc/php/<ver>/fpm/conf.d/`. The reference compose layout in this directory ([`docker-compose.yml`](docker-compose.yml) + [`php-overrides.ini`](php-overrides.ini)) is for this image.

The TL;DR PHP / MySQL settings in [`MISP_TUNING.md`](../../MISP_TUNING.md) are identical for both; only the file paths differ. The reference `php-overrides.ini` in this directory sets larger values than the TL;DR (`memory_limit` 8G, `post_max_size` and `upload_max_filesize` 512M, `max_execution_time` and `max_input_time` 3600), meant for a MISP host with 16 GB or more; on a smaller host, edit it to the TL;DR values first.

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — The image-choice section notes that the reference `php-overrides.ini` sets larger values than the TL;DR settings; history moved to this section.
- 2026-04-21 — Image-choice section and the `MISP_TUNING.md` cross-reference added.
