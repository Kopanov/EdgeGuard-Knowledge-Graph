# EdgeGuard versioning (CalVer)

## Scheme

We use **calendar versioning** for the distributable package:

- **Format:** `YYYY.M.D` (e.g. `2026.4.26` for 26 April 2026).
- **PEP 440 / PyPI:** Dotted segments are compared numerically (`2026.3.20` is valid).

`2026.03.20` with zero-padded month/day is also fine in many tools, but **PyPI normalization** tends toward `2026.3.20`; we standardize on **no unnecessary leading zeros** in `pyproject.toml` for consistency with PEP 440 examples.

## When to bump

- Bump **`[project].version` in `pyproject.toml`** when you cut a **release** you want others to report (tag, Docker image label, paper snapshot).
- **Do not** bump automatically on every local `git pull` or daily commit — that would create meaningless churn and merge conflicts.

For ad-hoc identification of an arbitrary checkout, use **`edgeguard version`** (prints package version + **git short SHA** when `.git` is present).

## Where it appears

| Location | Role |
|----------|------|
| `pyproject.toml` → `version` | Source of truth for `pip install` / `importlib.metadata` |
| `edgeguard version` | Human + support: CalVer + optional `git rev-parse --short` |

## Alternatives considered

- **SemVer (`1.2.3`):** Better when you need strict API compatibility promises; we may adopt a hybrid later (e.g. CalVer + build metadata).
- **Date-only tags without bumping pyproject:** Possible for Git-only flows; keeping `pyproject.toml` in sync avoids “unknown” versions in installed wheels.

---

_Last updated: 2026-04-26 — PR-N33 docs audit: refreshed example version. Prior: 2026-04-24._
