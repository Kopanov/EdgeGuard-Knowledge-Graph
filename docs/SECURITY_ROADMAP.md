# EdgeGuard Security Roadmap

This document describes EdgeGuard's **trust-boundary** defenses — the
controls that protect the knowledge graph against hostile or
misconfigured upstream feeds. It is a staged roadmap: each tier raises
the bar one step without breaking existing operators. Tiers 1 and 2 are
in place; Tier 3 is planned.

## Threat model in one paragraph

EdgeGuard ingests data from MISP, which acts as the single source of
truth for indicators, malware, threat actors, techniques, tactics,
tools, and CVE vulnerability data. **MISP is not trusted by default**:
anyone with write access to the MISP instance (a federated peer, a
compromised user, a misconfigured community feed) can create events
and attach tags such as `original_source:nvd` or
`edgeguard:source:vt`. Without an additional check, the source-truthful
timestamp pipeline would treat those forged tags as authoritative —
corrupting `MIN(r.source_reported_first_at)` exports to ResilMesh. The
**MISP tag-impersonation defense** is the trust-boundary control
against this.

## The defense

The defense is implemented in `src/source_trust.py` and exposed via
two environment variables:

| Env var | Effect |
|---|---|
| `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` | CSV of `Orgc.uuid` values that are trusted to publish source-truthful attributes |
| `EDGEGUARD_TRUSTED_MISP_ORG_NAMES` | CSV of `Orgc.name` values (NFKC-normalized + casefolded) trusted to publish source-truthful attributes |

When at least one of these is populated, every MISP attribute that
carries a `original_source:*` or `edgeguard:source:*` tag has its
**parent event's `Orgc` (creator organization)** checked against the
allowlist. Non-matching events' claims are dropped and counted via
`edgeguard_source_truthful_creator_rejected_total`.

When **both** env vars are empty, the defense is **DISABLED** — all
claims are accepted. This keeps a deployment that has not configured
the allowlist working; Tier 2 makes that state visible.

## Roadmap tiers

### ✅ Tier 1 — Defense machinery (in place)

- `source_trust.py` implements the creator-org allowlist check
- Unicode-aware name normalization (NFKC + casefold) defeats
  homoglyph attacks
- **Zero-width / bidi-control / variation-selector characters** (37,
  `node_identity._ZERO_WIDTH_AND_BIDI_CHARS`, including the combining
  grapheme joiner U+034F, the variation selectors VS1–VS16 and the
  Arabic letter mark U+061C) are stripped before the placeholder-name
  check (`is_placeholder_name`) and in the read-side IOC normalization
  (`ioc_normalize.refang`). This defeats invisible-character
  placeholder bypass (e.g. `"unknown​"` passing the placeholder
  filter). Natural keys themselves keep these characters
  (canonicalization applies NFC + trim only), so a name with a
  trailing U+200B and the same name without it remain two nodes.
  Cross-script confusables (Cyrillic 'о' U+043E vs Latin 'o' U+006F)
  are a known residual — fixing them requires a confusables library,
  which no tier of this roadmap covers yet.
- Strict UUID validation defeats free-text spoofing
- Log-injection-safe rejection logging (truncated, newline-stripped
  `Orgc.name`)
- `edgeguard_source_truthful_creator_rejected_total` Prometheus
  counter fires on every rejection

### ✅ Tier 2 — Observability for the disabled state (in place)

When the defense is configured OFF (both allowlists empty), the
state is **always visible** — not silent.

- **Startup log signal (all envs):**
  - `INFO` line when the defense is ACTIVE: `MISP tag-impersonation
    defense ACTIVE (EDGEGUARD_ENV=prod, trusted_uuids=3,
    trusted_names=0).`
  - `WARNING` line when the defense is DISABLED, in every environment —
    including when `EDGEGUARD_ENV` is unset (logged as
    `EDGEGUARD_ENV=unset`; Compose forwards it empty unless `.env` sets it):
    `MISP tag-impersonation defense is DISABLED (EDGEGUARD_ENV=unset)
    — all source-truthful claims accepted without creator-org
    verification...`

- **Prometheus gauge:**
  `edgeguard_misp_tag_impersonation_defense_disabled`
  - Value `1` → defense DISABLED
  - Value `0` → defense ENABLED
  - Labelless by design. Set when a process imports
    `src/metrics_server.py`, from that process's environment; on the
    Compose stack every Airflow task process that loads it writes the
    value (multi-process mode, the most recent write is served by the
    `metrics` service)

**Why the warning fires in every environment:** `config.EDGEGUARD_ENV`
defaults to `dev` (`src/config.py:26`, a label only; the API security
gate `config.is_production_env()` treats unset as production). A
warning limited to prod/staging would leave a brand-new deployment
with the defense off and no warning until an operator set the
variable. The warning therefore fires in **every** environment, and
the gauge exposes the state to any alert rule.

**Suggested alert rule** (see `docs/PROMETHEUS_SETUP.md`):

```yaml
- alert: EdgeGuardMispTagImpersonationDefenseDisabled
  expr: edgeguard_misp_tag_impersonation_defense_disabled == 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: MISP tag-impersonation defense is disabled
    description: |
      EdgeGuard accepts source-truthful claims from MISP attributes
      without verifying the creator organization. Any MISP user or
      federated peer can spoof source_id values and corrupt
      source_reported_first_at aggregates. Configure
      EDGEGUARD_TRUSTED_MISP_ORG_UUIDS and/or
      EDGEGUARD_TRUSTED_MISP_ORG_NAMES to enable the defense, then
      recreate the airflow container (docker compose up -d airflow; on
      a bare-metal install restart the collector and metrics-server
      processes). See docs/SECURITY_ROADMAP.md.
```

### 📋 Tier 3 — Fail-closed boot refusal (planned, post-Tier 2)

After operators have had a deployment cycle to configure the
allowlists (signalled by the Tier 2 log + gauge), the default for
`EDGEGUARD_ENV ∈ {prod, staging, production, stage}` will become
**fail-closed**: the process refuses to boot unless EITHER
an allowlist is configured OR
`EDGEGUARD_ALLOW_UNTRUSTED_MISP=1` is set explicitly as an opt-out.

Rationale:
- Boot refusal is self-documenting — operators can't accidentally
  deploy without making a conscious trust decision
- Log warnings can be missed; Prometheus alerts can be unwired;
  boot refusal cannot be missed
- Dev loop keeps the warn-on-empty ergonomics (no friction
  for local stacks where MISP runs inside the same compose network)
- Opt-out flag preserves escape hatch for operators with legitimate
  untrusted-MISP use cases (e.g. a known-curated community MISP
  they've explicitly decided to trust as a whole)

Tier 3 is planned as a separate change, after Tier 2 has had enough
operator exposure to surface any unexpected interaction.

## Operator checklist

1. **Find your EdgeGuard collector's `Orgc.uuid`.** In MISP, go to
   *Administration → List Organisations → [your org] → UUID*. Copy
   the canonical 8-4-4-4-12 hex string.

2. **Set the env var.** In your `.env` or deployment config:
   ```
   EDGEGUARD_TRUSTED_MISP_ORG_UUIDS=11111111-2222-3333-4444-555555555555
   # For multiple trusted orgs (e.g. after org migration, or multi-tenant):
   EDGEGUARD_TRUSTED_MISP_ORG_UUIDS=uuid-of-primary,uuid-of-backup
   ```

3. **Recreate the Airflow container** (`docker compose up -d airflow`; a
   `restart` keeps the old environment). Every Airflow task process that
   loads `metrics_server` writes the gauge (multi-process mode, the most
   recent write wins), and the `metrics` service serves it, so it reads
   `0` after the first task run in the recreated container. Restarting
   the `metrics` service alone has no effect. On a bare-metal install,
   restart the collector and metrics-server processes.

4. **Verify.** Check the log for
   `MISP tag-impersonation defense ACTIVE` (INFO) and the gauge
   for value `0`:
   ```
   curl -s http://localhost:8001/metrics | \
     grep edgeguard_misp_tag_impersonation_defense_disabled
   # Should report value 0
   ```

5. **(Recommended)** Add the alert rule from `PROMETHEUS_SETUP.md`.

## Cross-references

- `src/source_trust.py` — defense implementation
- `src/metrics_server.py` — Prometheus gauge wiring
- `tests/test_source_trust.py` — 47 tests covering both the decision
  logic and the disabled-state observability
- `docs/PROMETHEUS_SETUP.md` — full metrics reference + alert rules
- `.env.example` — env var templates
- `docs/RUNBOOK.md` § 8 — operator triage tree for `_MispFallbackHardError`
- `docs/BASELINE_LAUNCH_CHECKLIST.md` step `[6]` — pre-launch unicode-bypass audit
- `scripts/audit_legacy_unicode_bypass_nodes.py` — read-only audit
  pairing with the `_ZERO_WIDTH_AND_BIDI_CHARS` Tier-1 defense above
  (see the appendix)

## Appendix: data written by earlier versions

A graph kept from a version whose placeholder-name check did not strip
the zero-width / bidi-control / variation-selector characters can hold
`Malware` / `ThreatActor` / `Tool` nodes whose name is a placeholder
padded with invisible characters (e.g. `"unknown​"`). The read-only
script `scripts/audit_legacy_unicode_bypass_nodes.py` (session in
`READ_ACCESS`) counts the nodes of these labels whose `name` contains a
character of `_ZERO_WIDTH_AND_BIDI_CHARS` and recommends one of: close
as no-op (0 hits), one-shot Cypher (1–10 hits), a migration (>10 hits).
It is step `[6]` of [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md);
[MIGRATIONS.md](MIGRATIONS.md) lists it with the other operator
scripts. A fresh baseline has no such nodes.

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — Corrected the character table (37 characters, stripped before the placeholder-name check and in the read-side IOC refang, not in natural-key canonicalization), the `EDGEGUARD_ENV=unset` warning and the gauge writers (every Airflow task process that loads `metrics_server`, served by the `metrics` service, so an allowlist change needs `docker compose up -d airflow`); the main text describes current behavior only, the legacy-node audit moved to the appendix, and Tier 2 is marked as in place.
- 2026-04-26 — Added the Tier 1 bullet on zero-width / bidi-control / variation-selector stripping and the read-only legacy-node audit, and cross-linked RUNBOOK § 8 and BASELINE_LAUNCH_CHECKLIST step `[6]`.
- 2026-04-25 — The stripped character table was extended with the combining grapheme joiner U+034F, the variation selectors VS1–VS16 and the Arabic letter mark U+061C, and the read-only audit `scripts/audit_legacy_unicode_bypass_nodes.py` was added for nodes written before the strip.
- 2026-04-24 — The placeholder-name check moved from NFC to NFKC normalization and began stripping 19 zero-width and bidi-control characters before it.
- 2026-04-20 — Tier 2: the disabled-defense warning, previously limited to prod/staging, fires in every environment, and the gauge `edgeguard_misp_tag_impersonation_defense_disabled` was added.
- 2026-04-18 — Tier 1: the creator-org allowlist defense against MISP tag impersonation (`src/source_trust.py`) was added for the source-truthful timestamp pipeline.
