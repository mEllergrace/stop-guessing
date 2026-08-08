# Changelog

All notable changes to STOP-GUESSING. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project uses semantic versioning and bumps `VERSION` on every code-changing push.

## [0.6.1] — 2026-08-06

### Fixed — evidence was written into the agent's shared config directory
Found by the operator, who spotted it before distribution: every path for data resolved under
`$CLAUDE_CONFIG_DIR` (e.g. `~/.claude-ies/stop-guessing/`). That directory belongs to the agent and
is shared by every session and every project on the profile.

Measured before changing anything: **31 state files, roughly 24 of them real Claude Code session
UUIDs**, pooled from whatever projects happened to be open. And each record carried `session_id` with
no `cwd` — so not one of them could be attributed to a project even in principle. A provenance tool
had produced two dozen unattributable records, in a directory that was not its own.

`stop_guessing/paths.py` is now the single resolver:
- **Default is `./.stop-guessing/`** — the directory the tool is called from. One ledger per project,
  attributable by construction.
- **Every state record carries `project`.** That was the other half of the defect; a record that
  cannot say where it came from is doing half its job.
- **`$STOP_GUESSING_HOME` overrides**, so a single-project machine or a central collector can still
  have one shared store. The default changed; the option did not close.
- **The old location stays readable and is reported** — 3 ledger records and 31 state files. Nothing
  was moved: relocating evidence without recording the move is exactly the ISO/IEC 27037 §5.4.1
  alteration this project refuses to perform silently.
- **The chain key stays in the profile deliberately** — it is a credential, not data, and a key beside
  a repository is no key at all. `stop-guessing.json` stays too: that is *configuration*, and the
  profile config layer is intended.

Scope, stated rather than implied: the **proof** ledger was never affected. `DEFAULT_LEDGER` has been
`repo_root() / ".stop-guessing" / "proofs.jsonl"` since `1c919e6`, the first commit that built the
prove machinery. All 1,623 proof records, the 21 claims and the AI-CAIQ derivation were always
project-local. What sat in the wrong place was 3 runtime records and a taint **cache** that
`persist.py` already documents as rebuildable from the authoritative ledger. Nothing had to be redone.

Still outstanding: `runtime/` (2.9 MB) remains in the profile directory because the hook sets
`PYTHONPATH` to it. By the same rule it does not belong there either, and it is flagged rather than
half-moved, since getting it wrong breaks every hook.

### Added — standards choices that can be re-opened, and 42001 first
`docs/frameworks.yaml` entries now carry two fields, both test-enforced:
- `alternatives_considered` — what else was weighed and why it lost, so a later reader can re-open
  the decision instead of inheriting it blind.
- `review` — a **trigger, not a date**. "Re-evaluate when ISO/IEC 42006 settles" survives contact
  with time; "reviewed 2026-08" does not. A standards choice written once as prose becomes the
  constraint the next reader inherits, which is the hand-written-status-block failure one level up.

**ISO/IEC 42001 now leads the ranking**, because it is the standard CSA is looking at for **Level 2
STAR for AI listings**. The through-line is exact: STAR Level 1 is self-assessment, which is what the
AI-CAIQ this toolchain already fills from its own proof records; Level 2 is third-party audited. So
42001 is the path from "we assessed ourselves" to "someone else certified us" — the same gap
`independently_reproduced: false` names internally.

Its row carries a **`scope_limit`**, enforced by a test: a management-system standard certifies an
*organisation*, never a piece of software. "42001 compliant" beside a product name would be precisely
the overclaim this file exists to prevent, so the row says *supports-evidence-for*, not *conforms-to*,
and names the clauses it can produce records for.

**ISO/IEC 27041 demoted to 5th, with the demotion recorded** rather than quietly corrected: its frame
is assuring *incident investigative* methods, and this is a continuous recorder that runs whether or
not anything is under investigation. It stays, because it remains right for the investigation case.
**ISO/IEC 15026** takes 2nd — assurance cases are what `claims.yaml` → proofs → `attest --self`
already is, in a standard vocabulary rather than a bespoke one — and **NIST CFTT / SWGDE** 3rd, being
an actual test methodology and the only entry that speaks to Daubert's known-error-rate limb.

### Fixed — four shipped surfaces still advertised `steer` as the default
Reported by the operator, who was still being asked for approval and went to the docs to find out
why. The default moved to `observe` in 0.5.2, but that changed only `DEFAULT_POSTURE` — and a
default is the **last** layer `resolve_posture` consults. Four surfaces went on stating the old one:

- `/custody-options` read "Default is `steer`", so the command that exists to explain the posture
  taught the wrong answer. Its resolution list also predated the managed floor (#47) and showed four
  layers where there are five.
- The generated project page said the same, via `cmd_page.py`.
- `.codex-plugin/plugin.json` declared `"posture_default": "steer"` — machine-readable policy, not
  prose. Nothing reads the key, which is the only reason it was harmless.
- `IMPLEMENTATION_PLAN.md` §2 decision 1 is left standing and marked **superseded**, not rewritten:
  that file records what was decided, and editing it to match the present would falsify the record.

`hook_gate.py:237` already said `DEFAULT_POSTURE` was named once "so `doctor` and the docs cannot
drift from the resolver". That was an intention with nothing enforcing it. `test_observe_never_prompts.py`
now scans every surface that asserts a default, and a second test feeds the three real pre-fix lines
back through the matcher so it cannot be quietly defanged into a test that always passes.

### Added — `scripts/set_posture.py`
Reads and writes the posture of a live profile, because nothing did. `doctor` reports the effective
posture but deliberately never changes it, and the resolution chain is per-profile — every layer but
the project one is keyed on `$CLAUDE_CONFIG_DIR`, so `~/.claude` and `~/.claude-ies` resolve
independently and fixing one does nothing for the other. Writing the value explicitly is also
version-robust: a profile running a pre-0.5.2 plugin honours layer 3 regardless of its built-in
default. Read-modify-write (the no-noodles keys in the same file are preserved), backup, atomic
replace. It reports a `managed.json` floor that would override the write rather than claiming a
success that did not happen, and never edits `managed.json` — that file exists so the recorded party
cannot weaken its own policy.

### Fixed — a test run wrote its evidence into the repository and then read it back
`paths.py` moved data out of the agent's shared config directory and into the directory the tool is
called from. Under pytest that directory is the repository, so every test touching a session wrote
`./.stop-guessing/state/<id>.json` into the working tree and left it there. State is cumulative by
design, which is what made it bite: the second run of the suite started with the first run's taint
already on disk, so a session that should have been on first touch of a classified artifact was over
the accumulation threshold instead.

    test_a_direct_read_of_the_real_path_still_works   expected `ask`, got `deny`
    test_dot_dot_traversal_to_a_classified_path...    expected `ask`, got `deny`
    test_subagent_merge_actually_changes_the_parent   parent already carried `restricted`

All three passed on a clean checkout and failed on a second run — order-and-history dependence
arriving through a filesystem rather than a fixture. `tests/conftest.py` now points
`$STOP_GUESSING_HOME` at a per-test temporary directory, which is the override `paths.py` already
documents. No product code changed and no assertion was weakened. The stale files were deliberately
NOT deleted: that directory also holds live session state, and this project does not delete evidence
to make a number look better.

### Fixed — `page build` refused while holding a perfectly good key (#90, third instance)
`cmd_page._key` looked at `--keyfile` and `$STOP_GUESSING_CHAIN_KEY` and nowhere else, so the
mode-600 keyfile `install.sh` writes was invisible and the page refused with "no chain key
available". `cmd_prove` had already fixed exactly this and said so in a comment; `cmd_ops` was fixed
next; the page was the half still doing it the old way. It now uses `discover(..., prefer_keyid=…)`
like the rest of the CLI. `--keyfile` still wins and the environment is still consulted.

Widening it exposed a second, worse failure that the narrow version had been accidentally hiding:
having *a* key is not having *the* key. A key that verifies nothing in the proof ledger satisfies a
`is None` check, `attest_self` then reads 0 proven because every entry fails its MAC, and the page
renders that as fact. `_render` now refuses on a keyid mismatch and names the key it needs, rather
than publishing a page that understates the project. Nothing re-keys the ledger — re-keying evidence
so that it verifies is the alteration this project exists to refuse.

### Added — `scripts/goal_status.py`
Answers "what stands between here and GOAL MET" **without** the chain key. `prove` and `attest` are
the real gate and correctly refuse unkeyed, but refusing also means an operator with no key learns
nothing — including which key is missing. Keyids are disclosable by construction, so this reports,
per ledger, the keyid it was written under and whether any provider here holds it; and splits every
declared surface by whether a proof run can drive it at all. It never prints key material, which is
asserted directly in its tests. It found that the custody ledger and the proof ledger are keyed
differently, and that only 5 surfaces across 2 claims genuinely require a live session.

### Fixed — the gate still wrote its ledger into the agent's config directory
The 0.6.1 entry above moved data out of `$CLAUDE_CONFIG_DIR`. It moved the `paths` resolvers and
`taint.persist.state_dir`, and it moved everything the CLI READS — and it missed `cli.gate.
ledger_path()`, which is the path the gate APPENDS every decision to. The regression test written
for that fix passed throughout, because it only ever asked the `paths` resolvers and never asked the
gate.

The result was a split ledger. `doctor`, `verify`, `export` and `state` all reported on
`<project>/.stop-guessing/ledger/custody.jsonl` while the gate wrote to the profile, so `doctor`
could report "138 records, intact, keyed, PASS" about a file that contained none of the gate's
records. A ledger nothing reads is not evidence, and two ledgers that disagree are worse than one.

The operator's requirement, stated directly: nothing is written to Claude's config directory or the
plugins directory during operation, and the ledger belongs to the project whose chain of custody it
records. `ledger_path()` is now `paths.ledger_file()`; `$STOP_GUESSING_HOME` still redirects it.
`gate.legacy_ledger_path()` keeps the old location reachable — records already written there are
left exactly where they are, because relocating evidence without recording the move is the
ISO 27037 §5.4.1 alteration this project refuses to perform silently.

`test_the_gate_never_writes_to_the_config_dir` now owns the location property and asserts what the
earlier test could not see: no `claude` component, no `plugins` component, and gate-write and
CLI-read resolving to the same file. The six gate fixtures point `$STOP_GUESSING_HOME` at a
profile-shaped directory so they keep asserting behaviour rather than encoding a location.

### Fixed — the same key supplied from a different provider was rejected as the wrong key
`_keyid` is `sg-<provider>-<digest-of-material>`, so identical key material yields
`sg-env-fd9a5112ed28` when read from the environment and `sg-kf-fd9a5112ed28` when read from a
keyfile. `discover(prefer_keyid=…)` compared whole keyids, so an operator moving their chain key out
of the environment and into a mode-600 keyfile — a deliberate improvement, tier 1 to tier 2 — was
told the ledger had been written under a different key, and every entry was reported as failing its
MAC. The MAC is computed over the material and verifies fine; only the comparison was wrong.

That is the #90 false-tampering family reached from the other side: there the wrong key was
selected, here the right key was refused. It also sat directly across the documented recovery path —
"supply the key via `$STOP_GUESSING_CHAIN_KEY` or `--keyfile`" — where the second option would have
been rejected for a ledger written under the first.

`keys.key_fingerprint()` strips the provider prefix and `keys.same_key()` compares on it. Both
`discover` and the page's keyid guard now use it. The provider prefix still distinguishes the
SOURCE, which is what the tier ordering needs; it is simply no longer treated as part of the key's
identity.

### Fixed — the recorder recorded nothing but its own crash
`hook_post.py` had `if __name__ == "__main__": raise SystemExit(main())` at line 136, with
`_cfg_dir`, `_record_loss` and `_content_binding` defined at 140, 147 and 175 — after it. Importing
the module defines all three; running it as a script does not, because `main()` is called before the
interpreter reaches those `def`s. The PostToolUse hook runs this module as a script, so the recorder
raised `NameError: name '_content_binding' is not defined` on every tool call and failed open.

Found live rather than by review: the project ledger held 220 records, every one of them a
`recorder.selfcheck` gap, growing by one per tool call, with not a single custody decision among
them. It had been that way since at least 2026-08-06.

Every signal said healthy. The module imports cleanly, so every test that imports it passed.
`doctor` reported "216 records, intact, keyed, PASS" — correctly, because a chain of crash records
is still an intact, correctly keyed chain. A recorder that records nothing while looking installed
is the worst failure available to this project, and it presented as a green check.

`_record_gap` made it far harder to find than it should have been: it wrote `NameError: <symbol>`
and nothing else — no file, no line, and no indication of which copy of the package was executing,
which is the whole question when a checkout, an installed runtime and a venv are all reachable. It
now records bounded frames (`file:line in function`, last 6, never source text) plus the resolved
interpreter, package path, version and cwd. The first record written after that change named the
defect immediately. `test_no_cli_module_defines_anything_after_its_main_block` checks the shape
across every CLI module, because this class is invisible to any test that imports rather than runs.

### Fixed — successful custody records went to the config directory, only the failures went home
With the gate's gap records moved project-local, the two halves of a session ended up in different
files: `recorder.client._direct` — the tier-0 in-process append, which is what an ordinary install
actually runs — still wrote through `daemon.ledger_path(cfg)` into `$CLAUDE_CONFIG_DIR`. So the
project ledger held only the failures and the profile ledger held only the successes, and neither
was the record of what happened.

Tier 0 now writes to `paths.ledger_file()`. Deliberately scoped: the daemon path is untouched,
because a daemon is per-profile while a ledger is per-project and reconciling those is a design
decision rather than a path substitution. Verified live — `tool.result`, `artifact.write` and
`artifact.derive` records now land in the project ledger.

### Added — the command boundary, so `command:` surfaces can be evidenced at all
`plugin:`, `skill:` and `command:` surfaces had no exerciser, and could not have had one: the
custody ledger deliberately records a prompt DIGEST and never the prompt, so it could prove that a
prompt happened and never which command it was. `runner._surface_findings` had nothing to consult,
and those five surfaces across CLAIM-17 and CLAIM-20 were structurally unvalidatable.

The operator set the boundary: *"the tracking boundary is the name of the slash command with its
full path including tool names and options. The tracking of those tools belongs inside those tool
boundaries."* `hook_lifecycle.command_boundary()` records exactly that — the command's name, the
file it is defined in, and the tools/options its frontmatter declares. All of it already ships
publicly in the plugin.

Arguments are deliberately not captured: they are prompt content, and the boundary is the command,
not what was said to it. What the command then *does* is recorded at each tool's own boundary by the
PreToolUse and PostToolUse hooks, which already carry it. The no-transcript property is therefore
unchanged — the ledger now says "`/custody` was invoked" and still nothing about the surrounding
prompt. Two of the five tests assert precisely that: arguments never reach the record, and neither
does the prompt body.

This is the recording half. `exercise_commands()`, which reads these records and feeds
`exercised_surfaces`, is not written yet — and had to come second, since an exerciser can only read
evidence something is already writing.

### Added — `{"record": false}`, so one project can stop being recorded
The only off switch was `$STOP_GUESSING_DISABLE`, which silences the recorder on the whole machine.
An operator who wanted a single project to stop being recorded — this repository recording itself,
most obviously — had no way to say that, and the nearest available control was a global one.

That gap has a cost beyond inconvenience, and it was paid in this session: asked to turn the
dogfooding off, the only mechanism that existed was machine-wide, so a per-project intent became a
per-machine change without anyone deciding it should be. An option that does not exist gets
substituted for by whatever is nearest.

`record` sits beside `posture` in `.stop-guessing.json` and follows the same precedence — project
first, profile as the default beneath it. Absent means `true`, so nothing changes for an install
that never sets it. Three scopes now exist, and `/custody-options` documents them smallest-first:

| Scope | How |
|---|---|
| One project | `{"record": false}` in `./.stop-guessing.json` |
| One profile | `{"record": false}` in `$CLAUDE_CONFIG_DIR/stop-guessing.json` |
| Everywhere | `STOP_GUESSING_DISABLE=1` |

Every hook honours it, not just the gate: a switch that silenced the gate alone would leave
`hook_post` still writing results and derivation edges for a project that had been switched off —
the loudest half of the recording, still running. The transition is recorded once, for the reason
#83 established for the global switch: absence of records must never read as absence of activity.

A `managed.json` floor overrides it entirely. That file exists so the recorded party cannot weaken
the policy it is recorded under (#47), and this key would otherwise be the cleanest possible lever
for exactly that — one line in a project file to stop being recorded at all.

### Fixed — the installer health-checked the one thing that needs no dependencies
`install.sh` validated a staged runtime with `import stop_guessing`, which succeeds with no
third-party module present: `yaml` is not imported until the gate actually classifies something,
because the policy and classification rules are YAML. The `cp -R` fallback taken whenever pip is
unavailable copies the package WITHOUT its dependencies — so the check passed, the runtime was
swapped in as live, and every real decision then failed on `import yaml`. `sg-hook` fails open by
design, so the outcome was a recorder that silently recorded nothing while looking installed. That
is the worst failure mode available to a chain-of-custody tool, because it does not look like one.
The staged runtime is now also checked for PyYAML, under the same interpreter that will run the
hooks, and refuses with a message naming the missing dependency.

## [0.6.0] — 2026-08-06

**Benchmarked, not merely aligned.** Asked which chain-of-custody and provenance frameworks this was
measured against, the honest answer turned out to be three — and the README implied many more. Trying
to substantiate the claim broke three things open.

### The framework posture is now measured and generated
- `docs/frameworks.yaml` is the machine-readable source of record: every framework, with a `tier`
  ordered **externally-validated → self-asserted → mapped → design-target → not-benchmarked →
  out-of-scope**. `externally-validated` requires a third party's validator to return a verdict AND a
  control proving it rejects a deliberately broken input. Nothing weaker may use the word.
- `scripts/benchmark_frameworks.py` runs those validators. `tests/test_frameworks_posture.py` asserts
  the published tier matches the measured result, so a claim cannot outrun its measurement — if a
  validator stops being obtainable, the row must drop to self-asserted rather than stay green.
- Rendered into **both** the README and the Pages site from that one file, replacing the hand-written
  Standards table that listed ISO/IEC 27037, SEC 17a-4(f) and FRE 902 in a single row — inviting the
  reader to conclude three frameworks were tested when one was a single-clause schema source, one an
  untested design target, and one had never been exercised at all.
- **Ten frameworks a reviewer would expect are now named as absent, with reasons**, rather than
  omitted: ISO/IEC 27041 (assurance of method — the closest external statement of this project's own
  goal), ACPO, EU AI Act Art. 12, SLSA, Daubert/Frye, ISO/IEC 27042-27043, NIST SP 800-86, NIST AI
  RMF, ISO/IEC 42001, NIST 800-53 AU. An omitted framework reads as an oversight; a declared one
  reads as a decision. Daubert's row records that this project **currently fails it**.
- The AICM row states its denominator: 14 controls evidenced of roughly 243. A control count read as
  coverage is the overclaim the denominator prevents.

### Fixed — found by trying to benchmark
- **#89: all three exporters crashed on the real ledger.** PROV, CASE/UCO and OTLP export were written
  against the gate's nested predicate, where `actor` is an object; `prove` and the lifecycle hooks
  write flat events where `actor` is a string. 1,493 live records are flat, so
  `stop-guessing export prov|case|otel` exited 1 for every format. The only export test fed a pytest
  *fixture* — the external review's central finding for the third time: a primitive validated while
  the path a user runs is broken. One shared normaliser now handles both shapes, and it **omits** the
  operator and delegation fields a flat record genuinely lacks rather than filling them: an export
  that invents a custodian is not a custody record.
- **#90: the tool accused its own ledger of tampering.** `cmd_ops._key()` omitted `prefer_keyid`, so
  it chose the best-protected key rather than the one the ledger was written under. Every entry then
  failed its MAC and `export`/`verify`/`doctor`/`state` reported *"chain broken at 0 — edited in
  place"*. Nothing was tampered with. `claims check` and `export` disagreed about whether the same
  file was forged. `cmd_prove._key` had done it correctly all along and its comment already described
  the failure mode; the fix existed and had never been applied to the other half of the CLI.
- **#92: the CASE export did not conform.** 4,488 SHACL violations from NIST's `case_validate`, all
  one root cause — `uco-action:startTime` emitted as a bare string where UCO requires a typed
  `xsd:dateTime`. Then 121 Info-level advisories: UCO asks that identifiers end in an RFC-4122 UUID.
  `case_validate` ships `--allow-info` and using it would have been this project's own worst habit —
  passing a check by lowering what is checked. The version nibble in UCO's regex permits `[0-5]`, so
  **UUIDv5 qualifies and is deterministic**; conformance and reproducibility were never in tension.
  Now **`Conforms: True`, no flags, no suppressions** — closing the plan's M6 acceptance criterion,
  which had been open and unmentioned since the plan was written and could not have been met while
  the export crashed.

### Fixed — a verdict must not depend on machine load (#91)
- `run_vendored()` gave each vendored hook a hard 30 s budget and `compat/replay.py` did the same per
  corpus case. Under contention — `prove` running beside the suite and a SHACL validator — CLAIM-16
  and CLAIM-17 both flapped UNPROVEN on `TimeoutExpired` with nothing actually wrong. The timeout is
  now a parameter with two named values: `VENDORED_TIMEOUT = 30` unchanged for `PreToolUse` (the
  documented budget is ~40 ms p95, and a long timeout in the hot path means one hung rule stalls every
  tool call) and `VENDORED_TIMEOUT_BATCH = 300` for proofs and replays. Headroom for measurement, not
  a relaxed assertion — the claim is that the rules still produce byte-identical output, and how long
  they take under contention is incidental to it.
- Recorded because it is the more useful half: threading that parameter through with a regex
  mismatched twice, once putting `timeout=` inside the inner `payload()` call and once **silently
  rewriting a fixture string literal** (`"print(1)\n"` became `"print(1, timeout=…)"`). The proof
  caught both. The string corruption would have changed what the test fed the hook with no error at
  all — a scripted change to data still has to be verified against the running system, which is the
  rule that caught it.

### Changed
- **No single organisation is named as the primary user or target customer.** `scripts/generalise_audience.py`
  removes that framing. CSA remains cited as the *publisher* of AICM and the AI-CAIQ, because the
  toolchain genuinely maps to those and reads that workbook — citing a standards body is not the same
  as naming a customer. `csa.coc/` and `csa-material` stay and are reported: they are technical
  identifiers already written into signed ledger entries, and renaming them would invalidate evidence.
- The conformance validators are a declared `[conformance]` extra, never a runtime dependency — a
  benchmark only its author can run is not a benchmark.

## [0.5.3] — 2026-08-05

Repo hygiene run properly, and the README rewritten to say what is currently true.

### Fixed — the README was making false claims about its own system
The Workflow audit section still said *"2 of the 9 planned events exist"* and *"seven of nine
planned hook events are not registered"*, and listed `reconcile()` as *"built and called by
nothing"*. All three had been fixed earlier the same day. It also described the chain key as read
from an environment variable at the *"weakest tier"* with *"keychain support unused"*, while the
live profile resolves a mode-600 keyfile at tier 2.

A reviewer checking those statements against the code would have found the documentation
contradicting the implementation — which, for a project whose entire claim is that its documentation
is derived from verified evidence, is the worst available failure. Every claim in the rewrite was
checked against the running system first.

The rewrite also leads with **what a proof is here** and **what this does not establish**, rather
than leaving both to later sections: `independently_reproduced` is false and unsettable from inside
this repository, five surfaces are structurally validated but not executed, the judge panel is not
independent, and 31 of 53 ABSENT audit findings rest on structural predicates.

### Fixed — repo hygiene
`repo-hygiene`'s `hardcoded-paths` check found 169 references. Triaged, and the shipped ones fixed:

- **13 personal absolute paths removed from shipped source.** `/Users/isme/work/CSA/roster.csv`
  appeared ten times in `stop_guessing/prove/procedures.py` and three times in tests. Classification
  matches the path as a *string* against `/work/CSA/`, so no file was ever read and behaviour is
  unchanged — but a reviewer reading it cannot tell that, and a reference implementation that
  *looks* like it reads a private CSA directory undermines its own proof. Now
  `/example/work/CSA/roster.csv`, which classifies identically and exists nowhere.
- **`scripts/hygiene_sweep.py` worked for one person.** Its default repo-hygiene location and its
  default scan patterns were both absolute paths under one developer's home — so the hardcoded-paths
  check could only find hardcoded paths belonging to whoever wrote it. Now a search list and
  home-derived patterns; `--hygiene-root` and `$REPO_HYGIENE_ROOT` are unchanged and still win.
- **The sweep's output is triaged.** It reported 165 findings against a clean repository, because a
  census counts strings and cannot know intent. It now separates shipped from untracked from
  deliberate, and excludes the `# build-ok:` provenance comments that `check_before_build.sh`
  *requires* — counting one project rule's mandated evidence as another rule's violation made the
  two contradict each other. Current state: **0 findings in shipped files.**

### Added
- `scripts/depersonalise_paths.py` + tests — re-runnable, with `--check`. Its load-bearing test
  asserts the synthetic fixture path classifies identically to the original, so the rewrite cannot
  silently change what a proof is proving. It refuses to touch `IMPLEMENTATION_PLAN.md`,
  `CHANGELOG.md` and `IMPLEMENTATION_LOG.md`: those record where each reused asset was found, and
  rewriting them would falsify the provenance record they exist to keep.

## [0.5.2] — 2026-08-05

Closing the *class*, not two more instances of it.

#87 and #88 were both found by the operator rather than by the suite, and both were the same shape:
**the tool overriding state it does not own.** Fixing them individually and calling the class an
"open risk" is not a control, so this release enumerates every way the tool can touch operator-owned
state and asserts each one is impossible or explicitly preserving
(`tests/test_operator_sovereignty.py`, 11 tests).

Writing that file found two more instances immediately, which is the argument for having written it.

### Fixed
- **install.sh clobbered operator-edited docs.** The vendored `no-noodle.md` and `noodle-options.md`
  were copied over `commands/` and `skills/` unconditionally. These are upstream's files and the
  operator may have edited their copy — precisely what happened to `check_before_build.sh`, where 63
  lines of local hardening sat in the installed file and upstream's own installer silently reverted
  them. An existing copy that differs is now left alone and reported; only an absent or
  byte-identical one is written.
- **`--uninstall` left seven executables behind.** It removed `coc_gate.sh` and `coc_post.sh` and
  none of the seven lifecycle scripts, so an "uninstalled" profile still carried our code in the
  operator's hooks directory while the registrations were gone. Leaving residue in a directory we
  do not own is the same class as taking something over.
- **`prove` could not tell you the tree was unstamped.** Every proof pins the version, so proving
  before stamping produces proofs the gate immediately invalidates — twenty-one at once, reported as
  a wall of `version changed since this proof` findings that look like a regression and mean only
  "you stamped last". It happened twice during 0.5.x, discarding two full runs. `prove` now refuses,
  names the drifting manifests, and says how to fix it. `--allow-version-drift` overrides it.

### Added
- **`doctor` reports the effective posture and where it came from.** It described the recorder in
  detail and said nothing about how much the tool is allowed to interrupt, so a profile sitting in
  `steer` looked identical to one on the shipped default and the only way to tell was to read the
  config chain by hand. `posture_source()` returns the value, the layer that set it, and the path to
  change — including when a managed policy overrode a project or profile setting. It **reports**:
  choosing the posture belongs to the operator, and a tool that "corrected" it to the documented
  default would be making exactly the decision it is supposed to be recording.
- `DEFAULT_POSTURE`, named once, so the docs and the resolver cannot drift apart.

### Verified rather than asserted
`tests/test_operator_sovereignty.py` covers: nothing is superseded that the dispatcher cannot run
(#87 generalised); operator-edited files are never clobbered, with the control that "never clobber"
has not become "never install"; unrelated hooks and settings survive installation; uninstall removes
every script and registration it added, keeps hooks it did not install, and preserves the ledger and
observation data; the gate has no grant channel (#88); `PostToolUse` and the lifecycle hooks reach
the host through no channel at all; and no code path writes an operator posture config.

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
