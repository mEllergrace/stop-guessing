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
