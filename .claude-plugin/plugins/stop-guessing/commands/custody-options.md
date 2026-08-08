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

## Switching recording off

Three scopes, smallest first. Prefer the smallest one that covers what you mean — reaching for a
machine-wide switch to serve a per-project intent is how one project's preference becomes everyone's.

| Scope | How |
|---|---|
| One project | `{"record": false}` in that project's `./.stop-guessing.json` |
| One profile | `{"record": false}` in `$CLAUDE_CONFIG_DIR/stop-guessing.json` |
| Everywhere | `STOP_GUESSING_DISABLE=1` in the environment |

`record` follows the same precedence as `posture` — project first, profile as the default beneath
it — and absent means `true`, so nothing changes for an installation that never sets it. It is
honoured by every hook, not only the gate: a switch that silenced the gate alone would leave results
and derivation edges still being written for a project you had switched off.

Whichever scope you use, the transition is recorded once, because absence of records must never be
readable as absence of activity. A `managed.json` floor overrides `record` entirely — that file
exists so the recorded party cannot weaken the policy it is recorded under, and this key would
otherwise be the cleanest possible lever for exactly that.

no-noodles keys (`no_ad_hoc_probes`, `check_before_build`, `risk_scoring`) keep working
unchanged, as do `# noodle-ok`, `# risk-ok` and `# build-ok:`.

Read-modify-write. Never overwrite the file; other keys belong to someone else.
