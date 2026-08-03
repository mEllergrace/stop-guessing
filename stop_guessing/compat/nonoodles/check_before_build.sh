#!/usr/bin/env bash
# PreToolUse hook — mechanical enforcement of "check before building" (no-noodle
# rule #4): a NEW script file dropped into a scripts/ dir is presumed to belong
# inside an existing pipeline script as a flag/option, not as a parallel one-off.
# Blocks Write calls that CREATE (not edit) a script-like file under a scripts/
# directory, unless the content carries an explicit justification marker.
# Input: JSON on stdin (tool_name, tool_input.file_path, tool_input.content).
# Exit 2 = block + surface message. Escape hatch: `# build-ok: <reason>` (or
# `// build-ok: <reason>`) anywhere in the new file's content.
# Discipline it enforces: ~/.claude/skills/no-noodle.md, rule 4.
# Real incident this responds to: reaching for scripts/resync_mismatches.py
# when verify_migration.py already had the diff logic that capability needed.

INPUT=$(cat)
TOOL=$(echo "$INPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tool_name',''))" 2>/dev/null)
[ "$TOOL" = "Write" ] || exit 0

# ADJUSTABLE / SWITCHABLE, same convention as no_noodle.sh:
#   off:  echo off > ~/.claude/check-before-build.state
#   on :  echo on  > ~/.claude/check-before-build.state   (or delete the file — default)
# Finer-grained, per-project or per-preference config (JSON, checked first) is
# available via the `/noodle-options` skill — see hooks/lib_config.sh.
STATE="$HOME/.claude/check-before-build.state"
HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_config.sh
source "$HOOK_DIR/lib_config.sh"
[ "$(resolve_state check_before_build "$STATE")" = "off" ] && exit 0

FILE_PATH=$(echo "$INPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))" 2>/dev/null)
CONTENT=$(echo "$INPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tool_input',{}).get('content',''))" 2>/dev/null)

# Phase 3 observation log (docs/RISK_MODEL_PLAN.md) -- same additive,
# never-blocking wiring as no_noodle.sh. This rule guards Write calls, not
# Bash commands, so the "command" logged is a synthesized `write <path>`
# signal rather than a literal shell command.
( source "$HOOK_DIR/lib_observe.sh" && risk_observe "write $FILE_PATH" "$FILE_PATH" ) >/dev/null 2>&1

[ -z "$FILE_PATH" ] && exit 0

# Only new files (Write on an existing path is an intentional overwrite/edit,
# already covered by "prefer Edit" norms elsewhere — not this hook's job).
[ -f "$FILE_PATH" ] && exit 0

# Only script-like files, and only inside a scripts/ directory -- the exact
# shape of the real incident. Narrower net on purpose: broaden later from
# evidence, same way no_noodle.sh's patterns grew one real case at a time.
case "$FILE_PATH" in
  */scripts/*.py|*/scripts/*.sh|*/scripts/*.js|*/scripts/*.ts|*/scripts/*.rb) ;;
  # Workflow blocks get the same check. Added 2026-07-30 after an incident where
  # workflows/ssm-mapping-run.json + mapping-consensus.json + akcm-emit.json already
  # defined the exact chain being built, and seven parallel scripts were written and
  # RUN against paid APIs without either dir being looked at.
  */workflows/*.json) ;;
  *) exit 0 ;;
esac

BASENAME=$(basename "$FILE_PATH")
# Test files are exempt: they're the natural, expected pairing with a script
# that already justified itself (or an existing script being extended).
case "$BASENAME" in
  test_*|*_test.py|*.test.js|*.test.ts) exit 0 ;;
esac

# --- THE SEARCH THE AGENT WAS SUPPOSED TO DO -------------------------------
# Why the hook does this rather than asking: the previous gate was a bare
# presence-check on a marker the agent writes ITSELF. On 2026-07-30 seven new
# scripts were created past it, each carrying a sincere '# build-ok:' whose
# justification was wrong, while workflows/ held the blocks being reimplemented.
# Self-certification cannot be the control. So: search, and put the hits in the
# refusal, so "nothing covers this" must be argued against a shown list instead
# of asserted into silence.
PROJ="$FILE_PATH"
while [ "$PROJ" != "/" ] && [ ! -d "$PROJ/.git" ]; do PROJ=$(dirname "$PROJ"); done
[ "$PROJ" = "/" ] && PROJ=$(dirname "$(dirname "$FILE_PATH")")

TOKENS=$(basename "$FILE_PATH" | sed 's/\.[^.]*$//' | tr '_.-' '\n\n\n' \
         | awk 'length($0)>3' | head -6)

CANDIDATES=""
if [ -n "$TOKENS" ]; then
  for T in $TOKENS; do
    HITS=$(grep -ril --include='*.json' --include='*.py' --include='*.sh' \
             --include='*.js' --include='*.ts' --include='*.md' \
             -e "$T" \
             "$PROJ/workflows" "$PROJ/scripts" "$PROJ/.claude/commands" 2>/dev/null \
           | grep -v "$FILE_PATH" | head -4)
    [ -n "$HITS" ] && CANDIDATES="${CANDIDATES}
  ── matching '$T':
$(echo "$HITS" | sed 's|^|     |')"
  done
fi

# --- MARKER VALIDATION -----------------------------------------------------
# A marker must show its work: name at least one path/dir actually searched, and
# say enough to be falsifiable. A bare '# build-ok: needed' is what got through
# before and no longer does.
MARKER=$(echo "$CONTENT" | grep -oE '(#|//) *build-ok:.*' | head -1)
if [ -n "$MARKER" ]; then
  REASON=${MARKER#*build-ok:}
  if [ "${#REASON}" -ge 60 ] && echo "$REASON" | grep -qE '(workflows|scripts|commands|\.json|\.py|\.ts|\.sh|/)'; then
    exit 0
  fi
  echo "CHECK-BEFORE-BUILD: the build-ok marker on $FILE_PATH does not show its work.
It must name what was actually searched and why the hits are unusable, e.g.
  # build-ok: searched workflows/ (no block covers X); scripts/ (nearest is Y — wrong because Z)
A bare marker is a self-signed waiver; that is exactly how seven parallel scripts
were created and run on 2026-07-30 with enforcement ON.
${CANDIDATES:+
Existing files matching this name — rule these out explicitly before re-asserting:$CANDIDATES}"
  exit 2
fi

echo "CHECK-BEFORE-BUILD: new file $FILE_PATH — do not create it until you have checked
whether an existing WORKFLOW BLOCK, script, or command already covers this (or could grow
a flag/option to cover it). Invoking a defined block beats writing a script that
reimplements it — that mistake costs the build AND the run.
$(if [ -n "$CANDIDATES" ]; then
    printf '\nCandidates found by this hook — open them before deciding:%s\n' "$CANDIDATES"
  else
    printf '\nThis hook found no name-matching candidates under workflows/, scripts/ or\n.claude/commands/. That is NOT clearance: it matched on filename tokens only.\nCheck by PURPOSE too.\n'
  fi)

If it is genuinely new, add '# build-ok: <what you searched, and why each hit is unusable>'
(must name a searched path, >=60 chars) and retry. See ~/.claude/skills/no-noodle.md rule 4."
exit 2
