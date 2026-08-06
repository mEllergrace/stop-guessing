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
# R2-026: one list, covering every event the plugin registers, so both supported install paths
# produce the same evidence.
LIFECYCLE = {
    "SessionStart": ("coc_session_start.sh", "Opening session..."),
    "UserPromptSubmit": ("coc_prompt.sh", "Recording prompt lineage..."),
    "PostToolUseFailure": ("coc_tool_failed.sh", "Recording failed call..."),
    "PreCompact": ("coc_precompact.sh", "Checkpointing custody..."),
    "SubagentStop": ("coc_subagent.sh", "Merging subagent taint..."),
    "Stop": ("coc_stop.sh", "Reconciling the turn..."),
    "SessionEnd": ("coc_session_end.sh", "Closing session..."),
}

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
for _event, (_script, _msg) in LIFECYCLE.items():
    ENTRIES[_event] = {"type": "command",
                       "command": f"bash {os.path.join(hooks_root, _script)}",
                       "statusMessage": _msg}

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
#
# #87: check_credentials.sh is deliberately NOT in this list. It is listed first in
# hook_gate.VENDORED_ORDER but has never existed in compat/nonoodles/ — it is an
# OPERATOR-installed hook, not part of moonsoup/no-noodles, so it was never ours to vendor.
# Removing its registration while being unable to execute it silently disabled the operator's
# credential hard-stop and downgraded it to a recorded finding.
#
# The rule this encodes: a tool may only take over a control it can actually run. Where it
# cannot, the operator's registration stays exactly where the operator put it. Vendoring their
# hook into a public distribution would "fix" the symptom by doing more of what caused it.
SUPERSEDED = ("no_noodle.sh", "check_before_build.sh", "risk_gate.sh")
OURS = ("coc_gate.sh", "coc_post.sh", *(s for s, _ in LIFECYCLE.values()))

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

# #70 (SG-HARD-037). settings.json was rewritten IN PLACE. An installer interrupted between
# truncate and write leaves a live profile with a half-written or empty settings.json — every
# hook gone, and the file that says how to get them back destroyed. Temp file in the same
# directory, fsync, then atomic rename; plus a timestamped backup of what was there before, so a
# bad rewrite is recoverable rather than merely detectable.
import shutil, tempfile, time

os.makedirs(claude_dir, exist_ok=True)
if os.path.exists(settings):
    backup = f"{settings}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(settings, backup)
    print(f"    backed up {os.path.basename(settings)} -> {os.path.basename(backup)}")

fd, tmp = tempfile.mkstemp(dir=claude_dir, prefix=".settings-", suffix=".json")
try:
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)  # indent=1 matches no-noodles' files
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, settings)          # atomic: readers see the old file or the new one
except BaseException:
    os.unlink(tmp)
    raise
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
    # #69 (SG-HARD-036). `pip install --target` into an EXISTING directory merges: a module a new
    # release deleted stays behind, recursive copies retain it, and the installer then stamps the
    # new version over a mixed runtime. A reported 0.4.0 install could be executing 0.3.0 code.
    # Build into a fresh directory and swap it in atomically; keep the previous one for rollback.
    local runtime="$state_dir/runtime"
    local staging="$state_dir/runtime.new.$$"
    rm -rf "$staging"
    mkdir -p "$staging"
    if python3 -m pip install --quiet --target "$staging" "$PKG_DIR" 2>/dev/null; then
      echo "  built the Python package into $staging"
    else
      cp -R "$PKG_DIR/stop_guessing" "$staging/"
      echo "  pip unavailable; copied the package into $staging"
    fi
    # The package reads VERSION and policy/rules relative to its root, so carry those too.
    for extra in VERSION policy rules docs; do
      [ -e "$PKG_DIR/$extra" ] && cp -R "$PKG_DIR/$extra" "$staging/" || true
    done

    # Health-check the staged runtime BEFORE it becomes the live one. A runtime that cannot
    # import is a broken profile, and swapping it in first would mean discovering that per hook.
    if ! python3 -c "import sys; sys.path.insert(0, '$staging'); import stop_guessing" 2>/dev/null; then
      echo "  REFUSED: the staged runtime at $staging does not import; leaving the existing one."
      rm -rf "$staging"
      return 1
    fi
    if [ -d "$runtime" ]; then
      rm -rf "$runtime.prev"
      mv "$runtime" "$runtime.prev"      # kept for rollback, not merged into
    fi
    mv "$staging" "$runtime"
    echo "  swapped in the new runtime (previous kept at $runtime.prev)"

    # R2-026. The marketplace plugin registers nine events; this path registered two, so the
    # installation advertised for superseding no-noodles silently omitted SessionStart,
    # UserPromptSubmit, PostToolUseFailure, PreCompact, SubagentStop, Stop and SessionEnd — the
    # very hooks CLAIM-11/13/14 name. Two supported install paths with different evidence is two
    # different products.
    for pair in "coc_gate.sh:hook_gate:Chain-of-custody gate" \
                "coc_post.sh:hook_post:Recording custody" \
                "coc_session_start.sh:hook_lifecycle SessionStart:Opening session" \
                "coc_prompt.sh:hook_lifecycle UserPromptSubmit:Recording prompt lineage" \
                "coc_tool_failed.sh:hook_lifecycle PostToolUseFailure:Recording failed call" \
                "coc_precompact.sh:hook_lifecycle PreCompact:Checkpointing custody" \
                "coc_subagent.sh:hook_lifecycle SubagentStop:Merging subagent taint" \
                "coc_stop.sh:hook_lifecycle Stop:Reconciling the turn" \
                "coc_session_end.sh:hook_lifecycle SessionEnd:Closing session"; do
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

    # §10.1: /no-noodle and /noodle-options must keep working after supersession. CLAIM-17
    # declares both, and neither install path shipped them — a user who supersedes no-noodles and
    # then removes it lost two slash commands the claim said would survive. Vendored byte-identical
    # from upstream and installed the same dual way; never rewritten here.
    for doc in no-noodle noodle-options; do
      if [ -f "$PKG_DIR/stop_guessing/compat/nonoodles/$doc.md" ]; then
        cp "$PKG_DIR/stop_guessing/compat/nonoodles/$doc.md" "$claude_dir/commands/$doc.md"
        cp "$PKG_DIR/stop_guessing/compat/nonoodles/$doc.md" "$claude_dir/skills/$doc.md"
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

write_daemon_plist() {
  # The tier-2 plist. Staged only — see the --isolated branch for why it is not installed yet.
  #
  # R2-007: every path is passed in. The previous version expanded $CLAUDE_DIR, which this script
  #   never assigns, so `set -u` aborted the installer on the first expansion.
  # R2-008: `pip install --target` creates a PACKAGE directory, not a virtual environment, so
  #   runtime/bin/python never existed. A real interpreter is resolved and pinned by path, with
  #   the runtime on PYTHONPATH — and that interpreter is an ambient dependency, recorded as one.
  # R2-009: --keyfile is passed. Without it recorder.daemon.main() exits 2 immediately.
  local out="$1" user="$2" runtime="$3" profile="$4" keyfile="$5"
  local interp
  interp="$(command -v python3)"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.mellergrace.stop-guessing.cocd.$(basename "$profile")</string>
  <key>UserName</key><string>${user}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProgramArguments</key>
  <array>
    <string>${interp}</string>
    <string>-m</string>
    <string>stop_guessing.recorder.daemon</string>
    <string>--config-dir</string>
    <string>${profile}</string>
    <string>--keyfile</string>
    <string>${keyfile}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>CLAUDE_CONFIG_DIR</key><string>${profile}</string>
    <key>PYTHONPATH</key><string>${runtime}</string>
  </dict>
  <key>StandardErrorPath</key><string>${profile}/stop-guessing/cocd.err</string>
</dict>
</plist>
PLIST
  chmod 0644 "$out"
}

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
      # #39 (SG-HARD-006). This set tier=2 because the ACCOUNT EXISTED, and then wrote a
      # LaunchAgent into ~/Library/LaunchAgents. launchd runs a LaunchAgent as the logged-in
      # user regardless of what target_uid says, so the recorder ran as the agent's own uid
      # while the installer printed "installing tier 2". Existence of an account is not
      # separation of authority.
      #
      # The flag still works and still does everything it can. What it no longer does is
      # report a tier it did not deliver. A real tier 2 needs a root-installed LaunchDaemon
      # in /Library/LaunchDaemons with UserName set, which this installer does not yet write.
      # #39 (SG-HARD-006), completed. A LaunchAgent runs as the logged-in user whatever
      # target_uid says, so tier 2 needs a root-installed LaunchDaemon with <key>UserName</key>.
      # That plist is now generated. Writing it requires root, which the installer does not
      # assume: with root it installs and bootstraps; without, it writes the plist somewhere
      # readable and prints the two commands, and installs tier 1 in the meantime — honestly.
      # R2-007..R2-014. The previous version of this branch could not work, and said it did:
      #   - it expanded $CLAUDE_DIR, which this script never assigns, under `set -u` (aborts);
      #   - the plist invoked runtime/bin/python, which `pip --target` never creates;
      #   - the plist passed no --keyfile, so the daemon exits 2;
      #   - the service account could not traverse the 0700 user-owned parent;
      #   - a tier-1 LaunchAgent was written afterwards under the SAME launchd label;
      #   - tier=2 was reported with no health check of any kind.
      #
      # Reporting a tier that does not run writes a false isolation_tier into every record, which
      # is worse than not offering the tier. Until the service architecture is built AND black-box
      # health-checked, this stages the artifacts, states precisely what is missing, and installs
      # tier 1 truthfully.
      local staged="$claude_dir/stop-guessing/com.mellergrace.stop-guessing.cocd.plist"
      write_daemon_plist "$staged" "$SERVICE_USER" "$runtime" "$claude_dir" "$keyfile"
      tier=1
      cat <<EOF
  service account $SERVICE_USER exists (uid $target_uid), and a candidate tier-2 LaunchDaemon
  plist has been staged at:

    $staged

  TIER 2 IS NOT INSTALLED, and this installer will not claim it. Reporting a tier that does not
  run would put a false isolation_tier into every record written. Outstanding work, tracked:

    - a real interpreter for the service (pip --target creates a package directory, not a venv)
    - service-owned paths separate from the 0700 user profile tree, so the account can traverse
    - a shared socket directory and group both identities can reach
    - an admitted-client uid so the daemon accepts the ordinary user's hook
    - per-profile launchd labels, so multiple profiles do not overwrite each other
    - a black-box health check (ping reports a different uid, keyed=true, append round-trips)

  Installing TIER 1: a separate recorder process with the key out of the environment, on your own
  uid — so you can still stop it. That is what tier 1 means and it is what you are getting.
EOF
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
