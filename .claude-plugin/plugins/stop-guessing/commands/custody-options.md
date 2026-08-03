---
name: custody-options
description: Configure STOP-GUESSING posture and enforcement per project or globally.
---

# /custody-options

Three postures ship. Default is `steer`.

| Posture   | Behaviour |
|-----------|-----------|
| `observe` | Records everything, blocks nothing. The postureless forbids still apply. |
| `steer`   | Asks on first touch of a classified artifact; denies on accumulation or egress. |
| `bar`     | The model does not open classified artifacts; signed scripts only, handles out. |

Resolution order, matching no-noodles' four-layer chain exactly:

1. `./.stop-guessing.json` (project)
2. `$CLAUDE_CONFIG_DIR/stop-guessing.json` (global)
3. legacy `.state` file
4. built-in default

no-noodles keys (`no_ad_hoc_probes`, `check_before_build`, `risk_scoring`) keep working
unchanged, as do `# noodle-ok`, `# risk-ok` and `# build-ok:`.

Read-modify-write. Never overwrite the file; other keys belong to someone else.
