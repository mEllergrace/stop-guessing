#!/usr/bin/env bash
# STOP-GUESSING installer.
#
# Structure, guarantees and hard-won details are taken from moonsoup/no-noodles' install.sh,
# which this supersedes. Four of its properties are load-bearing and are preserved exactly:
#
#   1. settings.json is READ-MODIFY-WRITTEN, never overwritten. Unrelated hooks survive.
#   2. Registration uses the RESOLVED ABSOLUTE path, never a literal `~`. A tilde expands at
#      hook-execution time under whatever HOME is then set — a real 2026-07-16 incident that
#      broke every CLAUDE_CONFIG_DIR=~/.claude-ies install.
#   3. Docs install to BOTH commands/ and skills/. A flat .md under skills/ is written to disk
#      and never loaded; only commands/<name>.md registers a slash command at user level.
#   4. --uninstall PRESERVES the accumulated evidence. Hooks and registrations go; the ledger,
#      the observation log and the shape counters stay. Audit trail is not disposable state.
#
# It does NOT run no-noodles/install.sh, ever. That installer overwrites the hardened
# check_before_build.sh with the stale 62-line repo copy (moonsoup/no-noodles#1).

set -uo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$PKG_DIR/VERSION")"

MODE="install"
PROFILES=()
ALL_PROFILES=0
SUPERSEDE=0
DRY_RUN=0
ISOLATED=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

  --profile <dir>            install into this CLAUDE_CONFIG_DIR (repeatable)
  --all-profiles             install into every ~/.claude* holding a settings.json
  --supersede-no-noodles     remove standalone no-noodles PreToolUse entries; the STOP-GUESSING
                             dispatcher runs the vendored rules in their original order
  --isolated                 install the recorder daemon under its own uid (isolation tier 2)
  --dry-run                  print the exact settings.json diff and change nothing
  --uninstall                remove hooks and registrations; PRESERVE the ledger and observations
  -h, --help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILES+=("$2"); shift 2 ;;
    --all-profiles) ALL_PROFILES=1; shift ;;
    --supersede-no-noodles) SUPERSEDE=1; shift ;;
    --isolated) ISOLATED=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

discover_profiles() {
  local found=()
  for d in "$HOME"/.claude*; do
    [ -d "$d" ] || continue
    [ -f "$d/settings.json" ] || continue
    found+=("$d")
  done
  printf '%s\n' "${found[@]}"
}

if [ "$ALL_PROFILES" -eq 1 ]; then
  while IFS= read -r p; do [ -n "$p" ] && PROFILES+=("$p"); done < <(discover_profiles)
fi
if [ ${#PROFILES[@]} -eq 0 ]; then
  PROFILES=("${CLAUDE_CONFIG_DIR:-$HOME/.claude}")
fi

# ── the settings.json surgery ────────────────────────────────────────────────
# Python rather than jq: jq is not guaranteed present, and this must not fail on a fresh machine.

apply_settings() {
  local claude_dir="$1" action="$2" dry="$3" supersede="$4"
  python3 - "$claude_dir" "$action" "$dry" "$supersede" "$PKG_DIR" <<'PYEOF'
import json, os, sys

claude_dir, action, dry, supersede, pkg_dir = sys.argv[1:6]
dry = dry == "1"; supersede = supersede == "1"
settings = os.path.join(claude_dir, "settings.json")

# RESOLVED ABSOLUTE path. Never a literal ~ — it expands at hook-execution time.
gate = os.path.join(os.path.realpath(claude_dir), "hooks", "coc_gate.sh")
entry = {"type": "command", "command": f"bash {gate}",
         "statusMessage": "Chain-of-custody gate..."}

data = {}
if os.path.exists(settings):
    with open(settings) as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError:
            print(f"  REFUSED: {settings} is not valid JSON; not touching it")
            sys.exit(3)

before = json.dumps(data, indent=1, sort_keys=True)
hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [{"hooks": []}])
if not pre:
    pre.append({"hooks": []})
group = pre[0].setdefault("hooks", [])

# no-noodles hook basenames whose STANDALONE registrations the dispatcher replaces.
SUPERSEDED = ("no_noodle.sh", "check_before_build.sh", "risk_gate.sh", "check_credentials.sh")

removed = []
if action == "uninstall":
    kept = [h for h in group if "coc_gate.sh" not in h.get("command", "")]
    removed = [h.get("command") for h in group if h not in kept]
    pre[0]["hooks"] = kept
else:
    kept = []
    for h in group:
        cmd = h.get("command", "")
        if "coc_gate.sh" in cmd:
            continue                      # dedupe our own, including a legacy tilde form
        if supersede and any(n in cmd for n in SUPERSEDED):
            removed.append(cmd)
            continue
        kept.append(h)
    kept.append(entry)
    pre[0]["hooks"] = kept

after = json.dumps(data, indent=1, sort_keys=True)
if dry:
    print(f"  [dry-run] {settings}")
    for r in removed:
        print(f"    - {r}")
    if action != "uninstall":
        print(f"    + {entry['command']}")
    if before == after:
        print("    (no change)")
    sys.exit(0)

if before == after:
    print(f"  {settings}: already correct")
    sys.exit(0)

os.makedirs(claude_dir, exist_ok=True)
with open(settings, "w") as fh:
    json.dump(data, fh, indent=1, sort_keys=True)   # indent=1 matches no-noodles' existing files
    fh.write("\n")
for r in removed:
    print(f"    - {r}")
if action != "uninstall":
    print(f"    + {entry['command']}")
PYEOF
}

install_profile() {
  local claude_dir="$1"
  echo "profile: $claude_dir"

  local hooks_dir="$claude_dir/hooks"
  local state_dir="$claude_dir/stop-guessing"
  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$hooks_dir" "$state_dir" "$claude_dir/commands" "$claude_dir/skills"
    chmod 700 "$state_dir"

    cat > "$hooks_dir/coc_gate.sh" <<EOF
#!/usr/bin/env bash
# STOP-GUESSING dispatcher — installed by install.sh $VERSION. Do not edit.
# Runs the vendored no-noodles rules in their original registration order, then the custody gate.
exec python3 -m stop_guessing.cli.hook_gate "\$@"
EOF
    chmod 755 "$hooks_dir/coc_gate.sh"

    # Docs to BOTH locations: only commands/ registers a slash command (2026-07-29 finding).
    for doc in custody custody-options; do
      if [ -f "$PKG_DIR/skills/$doc.md" ]; then
        cp "$PKG_DIR/skills/$doc.md" "$claude_dir/commands/$doc.md"
        cp "$PKG_DIR/skills/$doc.md" "$claude_dir/skills/$doc.md"
      fi
    done

    printf '%s\n' "$VERSION" > "$state_dir/VERSION"
    if [ "$SUPERSEDE" -eq 1 ]; then
      mkdir -p "$claude_dir/no-noodles"
      printf 'stop-guessing %s at %s\n' "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        > "$claude_dir/no-noodles/superseded-by"
    fi
  fi

  apply_settings "$claude_dir" "install" "$DRY_RUN" "$SUPERSEDE"
  [ "$ISOLATED" -eq 1 ] && echo "  isolation tier 2 requested (daemon under its own uid)"
  return 0
}

uninstall_profile() {
  local claude_dir="$1"
  echo "profile: $claude_dir"
  apply_settings "$claude_dir" "uninstall" "$DRY_RUN" 0
  if [ "$DRY_RUN" -eq 0 ]; then
    rm -f "$claude_dir/hooks/coc_gate.sh"
    rm -f "$claude_dir/commands/custody.md" "$claude_dir/commands/custody-options.md"
    rm -f "$claude_dir/skills/custody.md" "$claude_dir/skills/custody-options.md"
    rm -f "$claude_dir/stop-guessing/VERSION"
    # DELIBERATELY PRESERVED: ledger/, observations.jsonl, shapes/, session-trust.
    # Accumulated evidence is not disposable state — same rule no-noodles applies to its
    # observations dir, and more strongly here because this IS the audit trail.
    echo "  preserved: $claude_dir/stop-guessing/ledger and any observation data"
  fi
}

echo "STOP-GUESSING $VERSION — $MODE"
[ "$DRY_RUN" -eq 1 ] && echo "(dry run — nothing will be changed)"
for p in "${PROFILES[@]}"; do
  if [ "$MODE" = "uninstall" ]; then uninstall_profile "$p"; else install_profile "$p"; fi
done
echo "done."
