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

See also: [SETUP_GUIDE.md](../../SETUP_GUIDE.md), [SECRETS_MANAGEMENT.md](../../SECRETS_MANAGEMENT.md), and [MISP_SOURCES.md](../../MISP_SOURCES.md).

---

_Last updated: 2026-03-17 — Removed machine-specific paths; aligned with repo-agnostic deployment._
