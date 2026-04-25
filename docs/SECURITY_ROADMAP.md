# EdgeGuard Security Roadmap

This document tracks EdgeGuard's **trust-boundary** defenses — the
controls that protect the knowledge graph against hostile or
misconfigured upstream feeds. It is a staged roadmap, not a finished
design: each tier raises the bar one step without breaking existing
operators.

## Threat model in one paragraph

EdgeGuard ingests data from MISP, which acts as the single source of
truth for indicators, malware, threat actors, techniques, tactics,
tools, and CVE vulnerability data. **MISP is not trusted by default**:
anyone with write access to the MISP instance (a federated peer, a
compromised user, a misconfigured community feed) can create events
and attach tags such as `original_source:nvd` or
`edgeguard:source:vt`. Without an additional check, the source-truthful
timestamp pipeline (PR #41) would treat those forged tags as
authoritative — corrupting `MIN(r.source_reported_first_at)` exports to
ResilMesh. The **MISP tag-impersonation defense** (PR #44, Chip 5e) is
the trust-boundary control that fixes this.

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
claims are accepted. This is the "backward-compat" path for
operators who have not yet configured the allowlist.

## Roadmap tiers

### ✅ Tier 1 — Defense machinery (shipped, PR #44 + PR-N29 L1 + PR-N31)

- `source_trust.py` implements the creator-org allowlist check
- Unicode-aware name normalization (NFKC + casefold) defeats
  homoglyph attacks
- **Zero-width / bidi-control / variation-selector character stripping
  in natural-key canonicalization** (`src/node_identity.py:_ZERO_WIDTH_AND_BIDI_TRANSLATE`,
  shipped PR-N29 L1 with 17 chars, extended PR-N31 to 35 chars
  including CGJ U+034F + Variation Selectors VS1–VS16 + ALM U+061C).
  Defeats invisible-character key poisoning (e.g. `"unknown​"`
  bypassing the placeholder filter). The PR-N32 read-only audit
  script `scripts/audit_legacy_unicode_bypass_nodes.py` checks for
  legacy nodes that may have escaped this filter pre-PR-N29 L1.
  Cross-script confusables (Cyrillic 'о' U+043E vs Latin 'o' U+006F)
  are documented as residual — fixing requires a confusables library,
  tracked in Tier 2.
- Strict UUID validation defeats free-text spoofing
- Log-injection-safe rejection logging (truncated, newline-stripped
  `Orgc.name`)
- `edgeguard_source_truthful_creator_rejected_total` Prometheus
  counter fires on every rejection

### 🚧 Tier 2 — Observability for the disabled state (this PR, PR-I)

When the defense is configured OFF (both allowlists empty), the
state is now **always visible** — not silent.

- **Startup log signal (all envs):**
  - `INFO` line when the defense is ACTIVE: `MISP tag-impersonation
    defense ACTIVE (EDGEGUARD_ENV=prod, trusted_uuids=3,
    trusted_names=0).`
  - `WARNING` line when the defense is DISABLED, including the
    dev environment (which is the default):
    `MISP tag-impersonation defense is DISABLED (EDGEGUARD_ENV=dev)
    — all source-truthful claims accepted without creator-org
    verification...`

- **Prometheus gauge:**
  `edgeguard_misp_tag_impersonation_defense_disabled`
  - Value `1` → defense DISABLED
  - Value `0` → defense ENABLED
  - Labelless by design; read once at metrics-server boot

**Why widen from the prior prod/staging-only warning:**
`EDGEGUARD_ENV` defaults to `dev` in `src/config.py:17`. Under the
original gating (PR #44's `_warn_if_disabled_in_prod`), a brand-new
deployment would silently inherit "defense off + no warning" until an
operator remembered to flip the env var. Every new installation
shipped with a silent gap. PR-I closes that by emitting the warning
in **every** env and exposing the state via a gauge that any alert
rule can catch.

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
      restart the metrics server. See docs/SECURITY_ROADMAP.md.
```

### 📋 Tier 3 — Fail-closed boot refusal (planned, post-Tier 2)

After operators have had a deployment cycle to configure the
allowlists (signalled by the Tier 2 log + gauge), the
`EDGEGUARD_ENV ∈ {prod, staging, production, stage}` default will
flip to **fail-closed**: the process refuses to boot unless EITHER
an allowlist is configured OR
`EDGEGUARD_ALLOW_UNTRUSTED_MISP=1` is set explicitly as an opt-out.

Rationale:
- Boot refusal is self-documenting — operators can't accidentally
  deploy without making a conscious trust decision
- Log warnings can be missed; Prometheus alerts can be unwired;
  boot refusal cannot be missed
- Dev loop keeps the current warn-on-empty ergonomics (no friction
  for local stacks where MISP runs inside the same compose network)
- Opt-out flag preserves escape hatch for operators with legitimate
  untrusted-MISP use cases (e.g. a known-curated community MISP
  they've explicitly decided to trust as a whole)

Tier 3 will land as its own PR after Tier 2 has had enough operator
exposure to surface any unexpected interaction.

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

3. **Restart the collector and metrics server.** Both processes read
   the env var at boot.

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
  logic and the new PR-I observability
- `docs/PROMETHEUS_SETUP.md` — full metrics reference + alert rules
- `.env.example` — env var templates
- `docs/RUNBOOK.md` § 8 — operator triage tree for `_MispFallbackHardError` (PR-N31)
- `docs/BASELINE_LAUNCH_CHECKLIST.md` step `[6]` — pre-launch unicode-bypass audit (PR-N32)
- `scripts/audit_legacy_unicode_bypass_nodes.py` — read-only audit
  pairing with the `_ZERO_WIDTH_AND_BIDI_CHARS` Tier-1 defense above

---

_Last updated: 2026-04-26 — PR-N33 docs audit: added explicit Tier-1
sub-bullet for the PR-N29 L1 + PR-N31 zero-width / bidi-control /
variation-selector character stripping in natural-key canonicalization
(35 chars total at HEAD; pairs with `scripts/audit_legacy_unicode_bypass_nodes.py`
for legacy-graph audits). Cross-linked RUNBOOK § 8 + BASELINE_LAUNCH_CHECKLIST `[6]`._
