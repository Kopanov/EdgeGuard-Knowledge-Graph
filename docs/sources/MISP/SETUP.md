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

- **`harvarditsecurity/misp:latest`** — Apache mod_php; PHP config under `/etc/php/8.x/apache2/`. **Currently deployed for EdgeGuard.**
- **`coolacid/misp-docker:latest`** — php-fpm; PHP config under `/etc/php/<ver>/fpm/conf.d/`. The reference compose layout in this directory ([`docker-compose.yml`](docker-compose.yml) + [`php-overrides.ini`](php-overrides.ini)) is for this image.

The TL;DR PHP / MySQL settings in [`MISP_TUNING.md`](../../MISP_TUNING.md) are identical for both; only the file paths differ.

---

_Last updated: 2026-04-21 — Added image-choice section + MISP_TUNING.md cross-reference (PR-N4 round 2)._
