# Changelog

All notable changes to STOP-GUESSING. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project uses semantic versioning and bumps `VERSION` on every code-changing push.

## [0.2.0] — 2026-08-03

Implemented. `stop-guessing attest --self` exits 0: 21/21 claims proven by records in the
toolchain's own keyed ledger, 14 AICM controls evidenced, and the carried AI-CAIQ derived from
those proofs and filled last.

### Added
- **Ledger** — HMAC-keyed hash chain, JSONL sink refusing to append onto a broken or torn chain,
  seal-and-archive segments, keyed-nonce reconciliation, and alerting that escalates on an
  unrecognised op rather than dropping it.
- **Record schema** — in-toto Statement v1 envelope, DSSE, eight DEMM-Bench evidence regimes, and
  three requiredness tiers. `alterations: []` asserts; an absent key is refused at write.
- **Taint and policy** — label lattice with orthogonal flags, cross-process session persistence, a
  Cedar-shaped pure-Python PDP (`forbid` > `ask` > `permit`, deny by default), three postures.
- **Delegation** — script/test scaffolding that refuses to run untested, on a failing test, or on a
  script edited after its test passed.
- **Recorder isolation** — digest-pinned binary and hooks, PATH-shadow detection, ledger deny-listed
  under every posture including `observe`.
- **Proof machinery** — `prove`, `claims check`, `attest --self`, and the AI-CAIQ derived from
  proofs. `proofs:` is written only by `prove`.
- **Distribution** — `install.sh` with `--supersede-no-noodles`, plugin manifests for both
  ecosystems, and a project page generated from the attestation.
- `docs/REATTESTATION.md` — the approved re-run procedure.

### Fixed
- Accumulation did not work in production: session state was process-local while every hook
  invocation is a fresh process, so taint never survived between tool calls. Every proof passed
  because a proof runs in one process. CLAIM-07 now drives the real hook across six processes.
- `sufficiency` treated `known_gaps: []` as unpopulated, contradicting the schema rule it enforces.
- Deny-by-default caught the `observe` posture, making the safest rollout posture the harshest.
- `verify_sealed` crashed on a malformed appended record instead of reporting a finding.
- CI: two dead module paths, a non-existent subcommand, and a compat gate guarded by an empty
  directory git never committed — it had been silently skipping since M0.

### Notes
- Known gaps are listed in the README rather than omitted.
- `meta.version` in `claims.yaml` is now stamped by the writer; it had drifted.

## [0.1.0] — 2026-08-03

### Added
- `IMPLEMENTATION_PLAN.md` — complete, executable design: module architecture, custody record
  schema with required/optional tiers, taint state machine, hook wiring, no-noodles supersession
  contract, recorder isolation tiers, AI-CAIQ subsystem, and nine milestones each with a
  real-system acceptance test.
- Repository scaffolding: README, licence, issue forms, CI, project page.

### Notes
- No implementation yet. The plan is the deliverable at this version.
- Renamed from the working title "Chain of Custody" / `coc-prov`. `coc-prov` and `coc` are
  retained permanently as CLI aliases; the working directory keeps its original name.
