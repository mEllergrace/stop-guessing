---
name: custody-options
description: Configure STOP-GUESSING posture and enforcement per project or globally.
---

# /custody-options

Three postures ship. Default is `observe`.

| Posture   | Behaviour |
|-----------|-----------|
| `observe` | **Default.** Records everything, blocks nothing. The postureless forbids still apply. |
| `steer`   | Asks on first touch of a classified artifact; denies on accumulation or egress. |
| `bar`     | The model does not open classified artifacts; signed scripts only, handles out. |

`observe` is the default because the host already has a permission model the operator has
configured, and a second gate asking again is a recorder overriding a decision its user has already
made. `steer` and `bar` are unchanged and opt-in.

Resolution order — no-noodles' four-layer chain, with a managed floor above it (#47):

0. `$CLAUDE_CONFIG_DIR/managed.json` (**managed floor**, outside project write authority)
1. `./.stop-guessing.json` (project)
2. `$CLAUDE_CONFIG_DIR/stop-guessing.json` (global)
3. legacy `.state` file
4. built-in default

The managed floor sets a *minimum* strength along `observe` → `steer` → `bar`. Layers 1-4 may
tighten past it and are ignored where they would loosen it, so a project cannot weaken the policy
it is recorded under. Absent `managed.json` means no floor, which is the shipped state.

**The chain is per-profile.** Every layer but the project one is keyed on `$CLAUDE_CONFIG_DIR`, so
`~/.claude` and `~/.claude-ies` resolve independently and a change to one does not reach the other.
Run `stop-guessing doctor` under a profile to see its effective posture and which layer set it.

no-noodles keys (`no_ad_hoc_probes`, `check_before_build`, `risk_scoring`) keep working
unchanged, as do `# noodle-ok`, `# risk-ok` and `# build-ok:`.

Read-modify-write. Never overwrite the file; other keys belong to someone else.
