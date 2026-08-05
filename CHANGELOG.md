# Changelog

All notable changes to STOP-GUESSING. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project uses semantic versioning and bumps `VERSION` on every code-changing push.

## [0.4.0] — 2026-08-04

Repo hygiene, and the tooling to keep it that way.

### Removed from tracking
- **`build/` is no longer tracked.** 56 files under `build/lib` were committed against 66 real
  source files, so nearly half the Python on GitHub was a second, drifting copy of every module —
  eight of them carrying uncommitted modifications of their own. A reviewer reading
  `build/lib/stop_guessing/prove/runner.py` was reviewing a stale snapshot. `.gitignore` covered
  `__pycache__`, `.venv` and `*.egg-info` but never `build/`. Files stay on disk; only tracking goes.

### Fixed
- **The AI-CAIQ template is resolved, not hardcoded.** Three proof procedures pinned one
  developer's absolute path to CSA's blank workbook, so the proofs that the questionnaire is
  filled by the toolchain could only ever run on that one machine. They now go through
  `resolve_template()`, which already handled `--template`, `$STOP_GUESSING_CAIQ_TEMPLATE` and the
  known locations. This matters more than portability housekeeping: **the blank AI-CAIQ cannot be
  redistributed**, so it is absent from every repo by design and every operator must supply their
  own copy. A hardcoded path made that impossible to do.
- **A specific `forbid` now out-explains a generic one.** Two rules denied a credential egress and
  the generic one won attribution, because `max()` returns the first maximal element. The outcome
  was right either way, but the record said "the session held some taint" when what happened was
  "credential material left the host". Adds `Policy.priority`, which tiebreaks only *within* one
  effect and never across them — `forbid` > `ask` > `permit` is untouched, and ties still fall back
  to declaration order, so existing policy sets behave exactly as before.
- **`test_the_default_posture_is_observe` was not hermetic.** It passed no config dir and so read
  whichever `stop-guessing.json` the developer had installed; this machine's says `steer`, so the
  test asserted a default while measuring an opt-in — the same failure already recorded at
  `prove/runner.py:274`. Now hermetic, with a second test asserting the other direction: an
  installed config must still select its posture, and the project layer must still override global.

### Added
- **`scripts/attest_guard.py`** — snapshots the attestation, runs a command, snapshots again, and
  reports only what got *worse*. Repo work is safe or unsafe on facts nobody holds in their head:
  14 claims pin module paths in `must_touch`, so a `git mv` silently un-proves them, while deleting
  a build tree breaks nothing because every evidence ref is a ledger record id. It guards without
  freezing — a regression is a re-proving list, not a veto, and the output names the commands that
  re-bind. 9 hermetic tests.
- **`scripts/stamp_version.py`** — specified in the plan, never written, which is exactly how three
  manifests came to declare a stale version on the first bump after the plan warned against it.
  Detection already existed upstream in repo-hygiene; nothing wrote. Covers the nested case that
  caused the miss: a marketplace manifest declares no version of its own, only one per `plugins[]`
  entry. 8 tests.
- **`scripts/hygiene_sweep.py`** — runs the repo-hygiene checks against this one repo. The upstream
  driver is a fleet tool needing a projectMan database and a scan of an external drive; this
  imports the same checks unchanged and hands them a path.

## [0.3.0] — 2026-08-03

Acted on an independent review (18 findings, all accurate) plus two rounds of
adversarial self-testing that found three more.

### Added
- **Execution witness** — proof procedures run instrumented; the package modules they enter are
  recorded and claims declare `must_touch`. Closes the worst defect found: all 21 procedures could
  be replaced with `lambda: ProofResult(True)` and every claim still reported PROVEN.
- **Judge panel** (#29) — mechanical lenses over each procedure's *adequacy*, in rockin-robin's
  shape: **disapproval is deferred**, recorded and surfaced, never blocking. The `independence`
  lens dissents on all 21 and always will.
- **PostToolUse capture** — execution, success, generated artifacts and derivation edges.
- Seal MACs, ledger write locks, stable artifact identity, ledger-authoritative state, posture
  resolution, gap recording on gate failure, and the `verify / doctor / state / delegate / run /
  trust / policy` CLI surface.
- Fuzz suite (28 hostile payloads x 2 hooks) and a mutation-test suite (43 cases).

### Fixed
- The installed plugin wrote no custody record and registered no PostToolUse hook.
- Enforcement trusted a deletable cache; artifact ids came from per-process `hash()`; seals were
  unauthenticated; a keyed ledger accepted unkeyed appends; posture was hard-coded; a crashed gate
  returned success silently; `cat api_keys.txt` produced no artifact at all; the plugin assumed the
  package was importable; `install.sh` lacked `set -e`; the template path was machine-specific.
- The deployed path's own records scored 0/4 on the project's sufficiency measure because the gate
  never used `CustodyRecord`. Now 4/4, all eight regimes populated.
- `GOAL MET` accepted file existence as CAIQ evidence; it now binds the workbook digest.
- The Cedar export rendered inexpressible conditions as `true`, making unrepresentable rules
  universal. Now `false` — inert.
- Stopped calling proxy variables a sandbox.

### Notes
- Ordering is load-bearing: `prove --claim CLAIM-21` must be last, because it fills the workbook
  and pins its digest. Running `caiq fill` after it leaves a workbook no proof vouches for.
- 47 deferred disapprovals stand, including `control-present` on 19 claims (#33).

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
