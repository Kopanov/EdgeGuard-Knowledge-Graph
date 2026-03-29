# Contributing & pull requests

## Before you open a PR

Use **Python 3.12+** (see `pyproject.toml` `requires-python`; CI uses 3.12).

1. **Install dev deps:** `pip install -r requirements-dev.txt`
2. **Lint & format:** `make lint` (or `ruff check` / `ruff format --check` as in CI)
3. **Types (optional but recommended):** `make type-check`
4. **Tests:** `make test` — same env vars as CI (`NEO4J_*`, `MISP_*` dummies are set by the Makefile)

CI runs **Ruff**, **Mypy**, **pytest** (with coverage floor 30%), **Docker build**, and **pip-audit** — see [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## New CLI / version behavior

- **`edgeguard version`** / **`edgeguard update`** — covered by `tests/test_edgeguard_cli_light.py` (update path mocks `subprocess.call` so `install.sh` is not executed in CI).
- **CalVer** — bump `[project].version` in `pyproject.toml` only when cutting a release; see [`VERSIONING.md`](VERSIONING.md).

## Commits

Use clear messages (e.g. `test: add CLI smoke tests`, `ci: run PR workflow for all branches`). No secrets or real API keys in commits.

## Generated Airflow files (local installs)

If you run Airflow on the host (not only via repo `docker-compose.yml`), **do not commit** local metadata database files (Apache Airflow may create one in `AIRFLOW_HOME`), or any generated secrets/config you copy out of the container. Prefer Docker Compose metadata (**`airflow_postgres`**) for a clean, team-aligned setup. `airflow.cfg` and `webserver_config.py` remain listed in `.gitignore` for typical local layouts.

---

_Last updated: 2026-03-20_
