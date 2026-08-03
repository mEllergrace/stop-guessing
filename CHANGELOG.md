# Changelog

All notable changes to STOP-GUESSING. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project uses semantic versioning and bumps `VERSION` on every code-changing push.

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
