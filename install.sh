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

# -e as well as -uo pipefail (#25). Without it a failed cp, mkdir or settings rewrite was
# followed by the remaining steps and a final "done." — and for an installer that rewrites
# settings.json in a live profile, "it printed done" has to mean every step succeeded.
set -euo pipefail

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

# RESOLVED ABSOLUTE paths. Never a literal ~ — it expands at hook-execution time.
hooks_root = os.path.join(os.path.realpath(claude_dir), "hooks")
ENTRIES = {
    "PreToolUse": {"type": "command",
                   "command": f"bash {os.path.join(hooks_root, 'coc_gate.sh')}",
                   "statusMessage": "Chain-of-custody gate..."},
    # PostToolUse is what establishes whether the approved action actually ran, what it returned,
    # and which outputs derive from which inputs (#13). PreToolUse alone records requests.
    "PostToolUse": {"type": "command",
                    "command": f"bash {os.path.join(hooks_root, 'coc_post.sh')}",
                    "statusMessage": "Recording custody..."},
}

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

# no-noodles hook basenames whose STANDALONE registrations the dispatcher replaces.
SUPERSEDED = ("no_noodle.sh", "check_before_build.sh", "risk_gate.sh", "check_credentials.sh")
OURS = ("coc_gate.sh", "coc_post.sh")

removed, added = [], []
for event, entry in ENTRIES.items():
    groups = hooks.setdefault(event, [{"hooks": []}])
    if not groups:
        groups.append({"hooks": []})
    group = groups[0].setdefault("hooks", [])
    kept = []
    for h in group:
        cmd = h.get("command", "")
        if any(o in cmd for o in OURS):
            continue                      # dedupe our own, including a legacy tilde form
        if event == "PreToolUse" and supersede and any(n in cmd for n in SUPERSEDED):
            removed.append(cmd)
            continue
        kept.append(h)
    if action != "uninstall":
        kept.append(entry)
        added.append(entry["command"])
    groups[0]["hooks"] = kept

after = json.dumps(data, indent=1, sort_keys=True)
if dry:
    print(f"  [dry-run] {settings}")
    for r in removed:
        print(f"    - {r}")
    for a in added:
        print(f"    + {a}")
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
for a in added:
    print(f"    + {a}")
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

    # #17: the hook must be runnable without the repo happening to be on PYTHONPATH. Prefer a
    # real install into the profile; fall back to pointing PYTHONPATH at the package directory.
    local runtime="$state_dir/runtime"
    if python3 -m pip install --quiet --target "$runtime" "$PKG_DIR" 2>/dev/null; then
      echo "  installed the Python package into $runtime"
    else
      mkdir -p "$runtime"
      cp -R "$PKG_DIR/stop_guessing" "$runtime/"
      echo "  pip unavailable; copied the package into $runtime"
    fi
    # The package reads VERSION and policy/rules relative to its root, so carry those too.
    for extra in VERSION policy rules docs; do
      [ -e "$PKG_DIR/$extra" ] && cp -R "$PKG_DIR/$extra" "$runtime/" || true
    done

    for pair in "coc_gate.sh:hook_gate:Chain-of-custody gate" \
                "coc_post.sh:hook_post:Recording custody"; do
      local script="${pair%%:*}"; local rest="${pair#*:}"
      local mod="${rest%%:*}"
      cat > "$hooks_dir/$script" <<EOF
#!/usr/bin/env bash
# STOP-GUESSING — installed by install.sh $VERSION. Do not edit.
# PYTHONPATH is set explicitly so the hook does not depend on the repo being importable (#17).
export PYTHONPATH="$runtime\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m stop_guessing.cli.$mod "\$@"
EOF
      chmod 755 "$hooks_dir/$script"
    done

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
  [ "$DRY_RUN" -eq 0 ] && install_recorder "$claude_dir"
  return 0
}

# ── the recorder ─────────────────────────────────────────────────────────────
# Without this the "recorder" is library code inside the agent's own process, under the agent's
# own uid, with the chain key in the agent's own environment. Every isolation claim above tier 0
# was aspirational until the daemon existed.
#
#   tier 1  daemon on this uid      key separation + single writer; the agent can still kill it
#   tier 2  daemon on its own uid   the ledger is not writable by the agent at all
#
# Tier 2 needs a service account, which needs sudo. If that is not available the installer says
# so and installs tier 1 rather than printing a tier it did not achieve.

SERVICE_USER="_stopguessing"

install_recorder() {
  local claude_dir="$1"
  local runtime="$claude_dir/stop-guessing/runtime"
  local ledger_dir="$claude_dir/stop-guessing/ledger"
  local keyfile="$claude_dir/stop-guessing/chain.key"
  mkdir -p "$ledger_dir"

  if [ ! -f "$keyfile" ]; then
    python3 - "$keyfile" <<'PYKEY'
import os, secrets, sys
p = sys.argv[1]
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, secrets.token_bytes(32).hex().encode())
os.close(fd)
PYKEY
    chmod 600 "$keyfile"
    echo "  generated a chain key at $keyfile (mode 600)"
  fi

  local plist="$HOME/Library/LaunchAgents/com.mellergrace.stop-guessing.cocd.plist"
  local target_uid tier
  target_uid="$(id -u)"
  tier=1

  if [ "$ISOLATED" -eq 1 ]; then
    if id "$SERVICE_USER" >/dev/null 2>&1; then
      target_uid="$(id -u "$SERVICE_USER")"
      tier=2
      echo "  service account $SERVICE_USER exists (uid $target_uid) — installing tier 2"
    else
      cat <<EOF
  --isolated requested but the service account does not exist, so tier 2 is NOT installed.
  Create it, then re-run with --isolated:

    sudo dscl . -create /Users/$SERVICE_USER UserShell /usr/bin/false
    sudo dscl . -create /Users/$SERVICE_USER UniqueID 499
    sudo dscl . -create /Users/$SERVICE_USER PrimaryGroupID 499
    sudo dscl . -create /Users/$SERVICE_USER NFSHomeDirectory /var/empty
    sudo dseditgroup -o create -r "STOP-GUESSING recorder" -i 499 $SERVICE_USER

  Installing tier 1 instead: the recorder is a separate process with the key out of the
  agent's environment, but on the agent's own uid, so the agent can still stop it.
EOF
    fi
  fi

  if [ "$tier" -eq 2 ]; then
    # The asymmetry that IS the boundary: the agent may ask the recorder to record, and may not
    # write the record. Socket is group-reachable; the ledger directory is not agent-writable.
    sudo chown -R "$SERVICE_USER" "$ledger_dir" 2>/dev/null || true
    sudo chmod 750 "$ledger_dir" 2>/dev/null || true
    sudo chown "$SERVICE_USER" "$keyfile" 2>/dev/null || true
  fi

  mkdir -p "$(dirname "$plist")"
  cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.mellergrace.stop-guessing.cocd</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/env</string>
    <string>PYTHONPATH=$runtime</string>
    <string>python3</string><string>-m</string><string>stop_guessing.recorder.daemon</string>
    <string>--config-dir</string><string>$claude_dir</string>
    <string>--keyfile</string><string>$keyfile</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$claude_dir/stop-guessing/cocd.log</string>
</dict></plist>
EOF
  echo "  wrote $plist"
  echo "  start it with:  launchctl bootstrap gui/\$(id -u) $plist"
  echo "  recorder tier when running: $tier"
}

uninstall_profile() {
  local claude_dir="$1"
  echo "profile: $claude_dir"
  apply_settings "$claude_dir" "uninstall" "$DRY_RUN" 0
  if [ "$DRY_RUN" -eq 0 ]; then
    rm -f "$claude_dir/hooks/coc_gate.sh" "$claude_dir/hooks/coc_post.sh"
    rm -f "$HOME/Library/LaunchAgents/com.mellergrace.stop-guessing.cocd.plist"
    # The chain key is NOT removed with --uninstall: without it the accumulated ledger becomes
    # unverifiable, and destroying the ability to check evidence is not an uninstall.
    rm -rf "$claude_dir/stop-guessing/runtime"
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
