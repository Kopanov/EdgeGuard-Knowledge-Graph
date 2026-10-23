# Contributing & pull requests

## Before you open a PR

Use **Python 3.12+** (see `pyproject.toml` `requires-python`; CI uses 3.12).

1. **Install dev deps:** `pip install -r requirements-dev.txt`
2. **Lint & format:** `make lint` (or `ruff check` / `ruff format --check` as in CI)
3. **Types (optional but recommended):** `make type-check` (checks `src/`; CI runs Mypy on `src/` and `scripts/`)
4. **Tests:** `make test` — same env vars as CI (`NEO4J_*`, `MISP_*` dummies are set by the Makefile)

CI runs **Ruff**, **Mypy** (`src/` and `scripts/`), **pytest** (with coverage floor 30%), a **Neo4j integration** test, **Docker builds** of both images with **Trivy** image scans, and **pip-audit** — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## CLI and version behavior

- **`edgeguard version`** / **`edgeguard update`** — covered by `tests/test_edgeguard_cli_light.py` (update path mocks `subprocess.call` so `install.sh` is not executed in CI).
- **CalVer** — bump `[project].version` in `pyproject.toml` only when cutting a release; see [`docs/VERSIONING.md`](docs/VERSIONING.md).

## Documentation

Every document in the repository follows one convention:

- **Main text: current behavior, present tense.** The body of a document is a guide to how the system works today: settings, defaults, limits, commands, procedures, known limits, and the rationale for them ("because …"). It carries no pull request or issue numbers, no change dates, and no before/after narration.
- **Dates that are data stay.** A measurement stated with the dataset it came from, an external version (for example Airflow 3.3.2 or MISP 2.4.177), and a reference-data version are part of the main text.
- **Changes go to History.** Each change is recorded as a dated entry, newest first, one line each (`- YYYY-MM-DD — <what changed and why>`), in the document's `## History` section at the end, directly below a single `_Last updated: YYYY-MM-DD_` line. An entry whose day is not known carries `YYYY-MM` and follows the dated entries of that month.
- **The README has no History.** `README.md` ends with its single `_Last updated: YYYY-MM-DD_` line and carries no `## History` section; every other document keeps its History.
- **Planned work lives in `docs/ROADMAP.md`.** Other documents describe the current behavior and state its limits; the roadmap is the one document whose main text may link the open GitHub issue that tracks an item.
- **No procedures for data written by earlier versions.** After larger changes the project wipes MISP and Neo4j and runs a fresh baseline, so the documents describe a fresh deployment only: repairs and one-off migrations of data kept across an upgrade are not documented (git history keeps earlier procedures). A change that a reader needs in order to understand the current system is recorded as one dated History line.
- **Historical records keep their text.** `docs/flow_audits/`, `migrations/*.md` and `docs/DOCUMENTATION_AUDIT.md` record a past state; each opens with a one-line note that points to the current document. A design proposal is not kept once it is implemented: what stays true moves into the current document and git history keeps the proposal.

When a heading changes, its anchor changes too: update every link to the old anchor in the same pull request.

## Commits

Use clear messages (e.g. `test: add CLI smoke tests`, `ci: run PR workflow for all branches`). No secrets or real API keys in commits.

## Generated Airflow files (local installs)

If you run Airflow on the host (not only via repo `docker-compose.yml`), **do not commit** local metadata database files (Apache Airflow may create one in `AIRFLOW_HOME`), or any generated secrets/config you copy out of the container. Prefer Docker Compose metadata (**`airflow_postgres`**) for a clean, team-aligned setup. `airflow.cfg` and `webserver_config.py` remain listed in `.gitignore` for typical local layouts.

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — `README.md` carries only its `_Last updated` line, without a History section; planned work lives in `docs/ROADMAP.md`, which may link the issue tracking an item.
- 2026-10-18 — The STIX exporter design proposal left the historical records: its current content moved into docs/RESILMESH_QUICKSTART_STIX.md and the proposal was deleted; an implemented proposal is not kept.
- 2026-10-18 — Documents no longer keep procedures for data written by earlier versions; the project re-baselines after larger changes.
- 2026-10-18 — A History entry whose day is not known carries `YYYY-MM`.
- 2026-10-17 — Added the documentation convention (current behavior in the present tense, dated History entries, an appendix for data written by earlier versions, historical records marked as such) and renamed the section "New CLI / version behavior" to "CLI and version behavior".
- 2026-10-17 — The CI and versioning links resolve from the repository root; the CI list names the Neo4j integration job, the Trivy scans of both images, and Mypy's scope (`src/` and `scripts/` in CI, `src/` in `make type-check`).
- 2026-03-20 — Earlier revision of the guide; no change details recorded.
