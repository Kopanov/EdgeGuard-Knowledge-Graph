# EdgeGuard versioning (CalVer)

## Scheme

We use **calendar versioning** for the distributable package:

- **Format:** `YYYY.M.D` (e.g. `2026.4.26` for 26 April 2026).
- **PEP 440 / PyPI:** Dotted segments are compared numerically (`2026.3.20` is valid).

`2026.03.20` with zero-padded month/day is also fine in many tools, but **PyPI normalization** tends toward `2026.3.20`; we standardize on **no unnecessary leading zeros** in `pyproject.toml` for consistency with PEP 440 examples.

## When to bump

- Bump **`[project].version` in `pyproject.toml`** when you cut a **release** you want others to report (tag, paper snapshot).
- **Do not** bump automatically on every local `git pull` or daily commit — that would create meaningless churn and merge conflicts.
- Tag each release `vYYYY.M.D` on the commit that bumps the version, and publish it as a GitHub release.
- **A release for a past commit of `main`.** When downstream work was built against an earlier commit, release that
  commit's code as follows:
  - make a commit on top of it that changes only the version, and tag that commit;
  - do not rewrite `main`;
  - `main` keeps its own, later version.

  `v2026.11.6` was released this way from `ef38825` (#306). `main` continued with #307 and the bump to `2026.11.7`.

For ad-hoc identification of an arbitrary checkout, use **`edgeguard version`** (prints package version + **git short SHA** when `.git` is present).

## Where it appears

| Location | Role |
|----------|------|
| `pyproject.toml` → `version` | Source of truth for `pip install` / `importlib.metadata` |
| `edgeguard version` | Human + support: CalVer + optional `git rev-parse --short` |
| REST / GraphQL OpenAPI `version` | `package_version()` (`src/package_meta.py`) |
| `edgeguard_version` in enriched alerts | `AlertProcessor.VERSION` (`package_version()`) |
| Git tag `vYYYY.M.D` and GitHub release | the released commit; for a past commit, a version-only commit on top of it |

## Alternatives considered

- **SemVer (`1.2.3`):** Better when you need strict API compatibility promises; we may adopt a hybrid later (e.g. CalVer + build metadata).
- **Date-only tags without bumping pyproject:** Possible for Git-only flows; keeping `pyproject.toml` in sync avoids “unknown” versions in installed wheels.

---

_Last updated: 2026-11-07_

## History

- 2026-11-07 — Releases are tagged `vYYYY.M.D` and published on GitHub; a past commit of `main` is released by a version-only commit on top of it (`v2026.11.6` from `ef38825`); `main` moved to `2026.11.7`.
- 2026-10-17 — Removed the Docker image version label from "Where it appears" (no image carries one) and added the REST / GraphQL OpenAPI `version` and the `edgeguard_version` of enriched alerts; the main text describes current behavior only.
- 2026-04-26 — Refreshed the example version.
- 2026-04-24 — Earlier revision of the policy; no change details recorded.
