# Implementation log

Append-only. Required per commit for any change touching the risk engine, the ledger chain
format, the record schema, or the vendored no-noodles tree — a rule inherited from
`no-noodles/skills/no-noodle.md:44-51`.

---

## 2026-08-03 — 0.1.0 — planning

Six parallel research passes (three over the local estate, three over published work) established
the reuse map, the standards posture, and the gap. Design pass produced the architecture.

Decisions that departed from the initial brief, each argued in the plan:

1. Cedar is **not** a runtime dependency. A Cedar-shaped pure-Python PDP ships instead, with
   `--pdp cedar` available as a backend and `cedar validate` running in CI only. `cedarpy` is
   third-party, absent, and a compiled dependency inside a per-tool-call `PreToolUse` hook
   contradicts "vendor the patterns, depend on nothing".
2. `steer` does **not** deny first touch. Denying read #1 taxes exploration and does nothing
   about read #12. It asks on first touch and denies on accumulation or egress.
3. The FRE 902 certifier is a **segment-level object**, not a per-record field. Rule 902(11)/(13)
   contemplates certifying a record set.
4. The chain is **HMAC-keyed**, in v1 rather than as later hardening. An agent with ledger write
   access can truncate a plain SHA-256 chain and recompute an entirely valid one — `verifyChain`
   would return `intact: true`.
5. OpenLineage export is a documented stub. It has no integrity semantics.
6. The working directory keeps the name `coc-prov`; only the product and repo are renamed.

Three pre-existing bugs in `moonsoup/no-noodles` were identified during the estate survey and
must be filed as issues before any fix: cross-profile state bleed (`$HOME/.claude` hardcoded in
two hooks while a third uses `$CLAUDE_DIR`), literal `~` in the default profile's hook
registrations, and 63 lines of hardening in the installed `check_before_build.sh` that were never
committed back — running `install.sh` silently reverts them.

## 0.5.0 — 2026-08-05 — the scope ratchet

The toolchain failed to catch its own author, and this release is the missing control.

Closing an earlier audit finding, eleven declared surfaces were withdrawn from `docs/claims.yaml`
because their proofs did not exercise them. That was true of each one. It was also what flipped the
`surface_validated` assurance axis to true — every edit moved a metric in the author's favour, and
nothing connected those two facts. The claim-definition digest noticed the claims had *changed*; it
has no notion of *direction*.

Recorded here because the design decision matters more than the code:

1. **A scope reduction is an ISO/IEC 27037 §5.4.1 alteration**, not a bespoke concept. §5.4.1 has
   always required a written justification for altering evidence, and the record schema has always
   made `alterations` a Tier-A field so `[]` is an assertion and absence is a finding. Reducing what
   a claim asserts alters the evidence subject. Editing YAML went around the mechanism the tool
   itself mandates. `stop-guessing retract` writes it through that mechanism.
2. **Narrowing stays legal; narrowing silently does not.** A claim that overreaches should be cut
   back. `claims.yaml` remains an editable text file — locking it would be theatre. What changed is
   that the silent path now leads somewhere visible.
3. **High-water, not last-value.** Shrinking one surface per commit would otherwise never register.
4. **The withdrawn surfaces were restored and fixed the other way**: `demo --posture steer` and
   `record emit` were built, the six `hook:` surfaces are driven as real subprocesses through the
   entry point `install.sh` registers, and `/no-noodle` + `/noodle-options` are vendored and
   shipped by both install paths.

**Risk-engine surface touched:** `stop_guessing/compat/nonoodles/MANIFEST.sha256` gained two
entries (`no-noodle.md`, `noodle-options.md`), vendored byte-identically from upstream. No hook,
lib, rule file or scoring path was modified — the docs were the only addition, and they exist
because CLAIM-17 promised those slash commands survive supersession and neither install path
delivered them.

**Security regression found and fixed on the live system (#87):** `check_credentials.sh` headed
`hook_gate.VENDORED_ORDER` and had never been vendored — it is an operator-installed hook, not part
of no-noodles. `--supersede-no-noodles` removed its registration anyway while the dispatcher could
not execute it, so the operator's credential hard-stop stopped firing and degraded to a logged
finding. `~/.claude-ies/settings.json` was found holding exactly one PreToolUse entry with the hook
file installed and unregistered. The rule this now encodes: **a tool may only supersede a control it
can actually execute.** Vendoring the operator's hook into a public distribution would have "fixed"
it by doing more of what caused it.

## 2026-08-05 — the gate was granting permission (#88)

Found by the operator, not by the suite: *"I think I just learned that the steer functions
circumvent our no-noodling policy."* Verified and correct.

`hook_gate.main()` emitted `permissionDecision: "allow"` on the warning path, under a comment
asserting that `allow` "does not interrupt". In Claude Code an explicit `allow` from `PreToolUse`
**auto-approves the call and suppresses the host's permission prompt**. The warning flag is set only
when an `ask` is downgraded because `permission_mode in ("bypassPermissions", "acceptEdits")` —
redundant under the first, a genuine grant under the second, since `acceptEdits` auto-accepts file
edits but still prompts for `Bash`.

The no-noodling interaction is the sharp end. `no_noodle.sh` allows the fetch-pipe-parser shape on
its **first** occurrence per project by design. On that occurrence the vendored rules exit 0, the
dispatcher proceeds, and the gate emitted `allow` — removing the single prompt at which the operator
could have declined. The tool shipped to record decisions was making them, and specifically was
disarming the policy it vendors.

Fixed by staying silent on that path: empty stdout with exit 0 is "no opinion", so the host's
permission model runs exactly as configured. The decision, reason and counterfactual are already in
the custody record, which is the tool's actual job. `deny` and `ask` are untouched; a DENY is still
never degraded, because bypassing prompts is not bypassing policy.

**Rule 3 escape used, and recorded as required:** writing `tests/test_gate_never_grants.py` was
blocked by the vendored `no_noodle.sh`, because the test fixture must contain the literal
fetch-pipe-parser shape the gate must not auto-approve. `# noodle-ok` was used on that single
command. The block itself is evidence the credential/no-noodle registrations restored under #87 are
live in `~/.claude-ies` again — the rule fired on its own author while fixing the rule's bypass.
