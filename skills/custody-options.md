---
name: custody-options
description: Configure STOP-GUESSING posture and enforcement per project or globally.
---

# /custody-options

**This records evidence. It does not seek permissions.**

Your host already has a permission model and you have already configured it. A second gate asking
again is a tool overriding a decision you have made. So the default posture is `observe`: it
records chain of custody and data provenance for every tool call and blocks nothing.

Enforcement is available and unchanged for anyone who wants it — it is opt-in, not the default.

| Posture   | Behaviour |
|-----------|-----------|
| `observe` | **Default.** Records everything, blocks nothing. |
| `steer`   | Opt-in. Asks on first touch of a classified artifact; denies on accumulation or egress. Under `bypassPermissions` an ask becomes an allow-with-warning, because that mode is a standing decision not to be interrupted. |
| `bar`     | Opt-in. The model does not open classified artifacts; signed scripts only, handles out. |

Resolution order, matching no-noodles' four-layer chain exactly:

1. `./.stop-guessing.json` (project)
2. `$CLAUDE_CONFIG_DIR/stop-guessing.json` (global)
3. legacy `.state` file
4. built-in default

no-noodles keys (`no_ad_hoc_probes`, `check_before_build`, `risk_scoring`) keep working
unchanged, as do `# noodle-ok`, `# risk-ok` and `# build-ok:`.

Read-modify-write. Never overwrite the file; other keys belong to someone else.

## The one refusal that survives `observe`

Writes to the tool's own ledger. That protects the record rather than policing you — a recorder
whose ledger can be overwritten has recorded nothing. Turn it off with
`{"protect_ledger": false}` if you want even that gone; the option stays open.
