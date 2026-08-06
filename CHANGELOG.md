# Changelog

All notable changes to STOP-GUESSING. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project uses semantic versioning and bumps `VERSION` on every code-changing push.

## [0.5.1] — 2026-08-05

### Fixed — the gate was granting permission (#88)

Found by the operator, not the suite: *"I think I just learned that the steer functions circumvent
our no-noodling policy."* Verified and correct.

`hook_gate` emitted `permissionDecision: "allow"` on the warning path, under a comment asserting
that `allow` "does not interrupt". It mistook the semantics — in Claude Code an explicit `allow`
from `PreToolUse` **auto-approves the call and suppresses the host's permission prompt**.

The flag is set only when an `ask` is downgraded because `permission_mode` is `bypassPermissions`
or `acceptEdits`. Redundant under the first; a genuine grant under the second, since `acceptEdits`
auto-accepts file edits but still prompts for Bash.

The no-noodling interaction is the sharp end: `no_noodle.sh` allows the fetch-pipe-parser shape on
its **first** occurrence per project by design. On that occurrence the vendored rules exit 0, the
dispatcher proceeds, and the gate emitted `allow` — removing the single prompt at which the operator
could have declined. The tool shipped to record decisions was making them, and was disarming the
policy it vendors.

Now silent on that path: empty stdout with exit 0 is "this hook has no opinion", so the host's
permission model runs exactly as configured. Nothing is lost — the decision, reason and
counterfactual were already in the custody record. `deny` and `ask` are untouched, and a DENY is
still never degraded, because bypassing prompts is not bypassing policy.

### Added
- `tests/test_gate_never_grants.py` — no `allow` in any permission mode, a source-level assertion
  that no allow-emission survives anywhere in the module, and a control confirming `deny`/`ask`
  still work, so "never allow" cannot be satisfied by a gate that says nothing at all.
- `tests/test_observe_never_prompts.py` — the default posture never asks, never denies and never
  grants, driven over five payload shapes in a hermetic profile, with the control that a write to
  the evidence ledger IS still refused.
- Structural validation for the surfaces a proof run cannot execute. `plugin:`, `skill:` and
  `command:` need a live agent session to drive, so "unvalidated" was conflating *not decidable
  here* with *nobody got round to it*. What ships, where, in what shape, registered by BOTH install
  paths, is now checked and a defect there is blocking. `surface_validated` still means EXECUTION —
  reporting it true because files are in the right place would be the same overclaim in a new place.

## [0.5.0] — 2026-08-05

The toolchain caught its own author, and the missing control is now a feature.

### The finding that produced this release

Closing an earlier audit finding, eleven declared surfaces were withdrawn from `docs/claims.yaml` —
six `hook:` entries, `plugin:`, `skill:`, two `command:` entries — plus two CLI surfaces that had
never been built. Each withdrawal was individually defensible: the proofs genuinely did not exercise
them. Collectively they were what flipped the `surface_validated` assurance axis to true. Every edit
moved a metric in the author's favour, and nothing in the ledger connected the two facts. The
claim-definition digest saw the claims had *changed*; it has no notion of *direction*, so
broadening and narrowing looked identical to it. A human reader caught it by asking whether the
goal had moved.

### Added
- **The scope ratchet** (`stop_guessing/prove/scope.py`). Each claim's declared surfaces and AICM
  control mappings are pinned to the ledger on every proof run. Scope may grow freely; it may
  shrink only through a recorded retraction carrying a reason. An unrecorded reduction is a finding
  on `claims check`, reported beside the verdict, so a reader sees the claim got smaller in the same
  breath as the number got better. Measured against the **high-water** scope, because nobody removes
  ten things at once — they remove one per commit.
- **`stop-guessing retract`** — records a reduction as an ISO/IEC 27037 §5.4.1 alteration with its
  written justification. §5.4.1 has always required this and the record schema has always made
  `alterations` a Tier-A field; editing YAML went around the mechanism the tool itself mandates.
  A retraction with no reason is refused at the source.
- **`stop-guessing demo --posture steer`** — §15's "the one command a reviewer runs", built rather
  than deleted. Drives first-touch `ask`, a derivation edge, the accumulation `deny`, the chain, and
  a tamper control, each citing the record that backs it, in a temp dir against a temp ledger. It
  runs its own controls: a clean session must egress freely, or "accumulation denies" would be
  satisfied by denying everything.
- **`stop-guessing record emit`** — M2's surface. Emits a Tier-A-validated in-toto Statement, and
  `--omit <field>` shows the refusal. `alterations: []` is accepted as a positive assertion;
  `alterations` absent is refused, because a reader cannot tell "nothing was altered" from "nobody
  looked". A test drops each of the 19 Tier-A fields in turn and requires every one to be refused.
- **Hook surfaces are driven, not asserted.** `exercise_hooks()` spawns the entry point `install.sh`
  registers as its own process, feeds it a realistic payload on stdin, and parses the response —
  in a hermetic `CLAUDE_CONFIG_DIR`, so exercising cannot write fixtures into the evidence ledger.
  The record states the limit exactly: the deployed code path with a *synthetic* caller, stronger
  than "registered in settings.json", weaker than "a live session exercised it".

### Fixed
- **Superseding disabled the operator's credential hard-stop (#87).** `check_credentials.sh` headed
  `hook_gate.VENDORED_ORDER` and was never in the vendored tree — it is an operator-installed hook,
  not part of no-noodles, so it was never ours to vendor. `--supersede-no-noodles` removed its
  registration anyway and the dispatcher could not run it, so the control degraded to a logged
  finding. Found live, not in a fixture: `~/.claude-ies/settings.json` had exactly one PreToolUse
  entry while the hook file sat installed and unregistered. The rule this encodes: **a tool may only
  supersede a control it can actually execute.** It now stays in `OPERATOR_RULES`, is never
  superseded, and is *verified still registered* — strictly more than was checked before.
  `scripts/repair_operator_rules.py` restores it where it was already lost.
- **`/no-noodle` and `/noodle-options` are shipped.** CLAIM-17 declared both and neither install
  path delivered them, so §10.1's promise that they survive supersession was undeliverable. Both
  docs are now vendored byte-identically with manifest entries, installed to `commands/` *and*
  `skills/`, and shipped by the plugin.
- **The wheel shipped none of the vendored tree.** `package-data` omitted `compat/nonoodles/`
  entirely, so `compat verify` had nothing to replay from a wheel — while passing from a checkout,
  which is how a packaging gap survives a green suite. The slow packaging test now verifies the
  vendored manifest *inside the installed package*.
- **`prove` could hang forever.** The surface exerciser inherited the caller's stdin, so a surface
  that reads it blocked indefinitely with no terminal — observed as ten minutes of wall clock
  against fourteen seconds of CPU, in a background run, producing no verdict at all. A release gate
  that never returns has failed open in the most expensive way available. `stdin` is now
  `DEVNULL`, timeouts are bounded, and a timed-out surface is not counted as exercised.
- **A silent `except: pass` disarmed the new control.** The scope record was written inside a bare
  handler so that "a scope record must never break a proof run" — which is precisely how a control
  comes to do nothing while reading as present. Zero scope records existed. Without a baseline the
  ratchet has nothing to measure against, so it now stops the run instead.
- **Scope records declared no gaps while the ratchet has one.** `known_gaps: []` is a positive
  assertion. The ratchet cannot detect a claim whose *statement text* is weakened while its surfaces
  hold constant — prose strength is not mechanically decidable here — so that limitation is written
  into `known_gaps` on every scope record rather than described only in prose.

### Restored
- All eleven withdrawn surfaces are back in `docs/claims.yaml`, and fixed the other way: the two
  missing CLI surfaces were built, the hooks are driven in real processes, and the two slash
  commands are shipped.

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
