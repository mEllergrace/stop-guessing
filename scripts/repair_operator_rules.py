#!/usr/bin/env python3
# build-ok: searched scripts/ and install.sh (install.sh registers OUR hooks and can remove
# superseded ones, but has no path that RESTORES an operator-owned registration it wrongly took
# over; attest_guard.py and hygiene_sweep.py check repo state, not live profiles) — nothing existing
# repairs a live settings.json, so this is new rather than a duplicate.
"""Restore operator-owned hook registrations that superseding removed (#87).

`check_credentials.sh` is the operator's credential hard-stop. It headed the dispatcher's
`VENDORED_ORDER` but was never in the vendored tree — it is not part of `moonsoup/no-noodles`, so
it was never ours to vendor. `install.sh --supersede-no-noodles` removed its PreToolUse
registration regardless, and the dispatcher could not execute it. The control stopped firing and
became a logged finding.

Found on the live system, not in a fixture: `~/.claude-ies/settings.json` had exactly one
PreToolUse entry (`coc_gate.sh`) while `~/.claude` still had all four. The hook file was present
and unregistered the whole time.

This restores the registration, in place, idempotently, with a backup — the same discipline
install.sh uses for its own writes. It never removes anything and never reorders our own entries.

    python3 scripts/repair_operator_rules.py --check          # report only, exit 1 if damaged
    python3 scripts/repair_operator_rules.py --profile DIR    # repair one profile
    python3 scripts/repair_operator_rules.py --all-profiles   # repair every ~/.claude*
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from stop_guessing.cli.hook_gate import OPERATOR_RULES  # noqa: E402

EVENT = "PreToolUse"


def missing_rules(settings: Path) -> list[str]:
    """Operator rules whose hook file exists but whose registration is gone."""
    try:
        data = json.loads(settings.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    registered = json.dumps(data.get("hooks") or {})
    hooks_dir = settings.parent / "hooks"
    out = []
    for rule in OPERATOR_RULES:
        if rule in registered:
            continue
        # Only restore what is actually installed. Registering a hook that does not exist would
        # make every tool call emit an error — a repair that breaks the session is not a repair.
        if (hooks_dir / rule).is_file():
            out.append(rule)
    return out


def repair(settings: Path, dry_run: bool = False) -> list[str]:
    """Re-register the operator's rules FIRST, before our gate. Returns what was restored."""
    gone = missing_rules(settings)
    if not gone or dry_run:
        return gone

    data = json.loads(settings.read_text(encoding="utf-8"))
    hooks = data.setdefault("hooks", {})
    groups = hooks.setdefault(EVENT, [{"hooks": []}])
    if not groups:
        groups.append({"hooks": []})
    group = groups[0].setdefault("hooks", [])

    hooks_dir = settings.parent.resolve() / "hooks"
    # Resolved absolute paths, never a literal ~ — it expands at hook-execution time under
    # whatever HOME is set then (the 2026-07-16 incident install.sh guards against).
    restored = [{"type": "command", "command": f"bash {hooks_dir / rule}"} for rule in gone]
    # Order matters: the credential check ran first in the original registration and must keep
    # running before anything that could surface a value.
    groups[0]["hooks"] = restored + group

    backup = settings.with_suffix(f".json.bak-{time.strftime('%Y%m%dT%H%M%S')}")
    shutil.copy2(settings, backup)
    tmp = settings.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(settings)          # atomic: an interrupted repair must not truncate settings.json
    return gone


def profiles(args) -> list[Path]:
    if args.profile:
        return [Path(p).expanduser() for p in args.profile]
    if args.all_profiles or args.check:
        return sorted(p for p in Path.home().glob(".claude*") if (p / "settings.json").is_file())
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", action="append", help="a CLAUDE_CONFIG_DIR (repeatable)")
    ap.add_argument("--all-profiles", action="store_true")
    ap.add_argument("--check", action="store_true", help="report only; exit 1 if damaged")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    targets = profiles(args)
    if not targets:
        ap.error("give --profile, --all-profiles or --check")

    damaged = 0
    for prof in targets:
        settings = prof / "settings.json"
        if not settings.is_file():
            print(f"{prof.name}: no settings.json, skipped")
            continue
        gone = missing_rules(settings)
        if not gone:
            print(f"{prof.name}: operator rules intact")
            continue
        damaged += 1
        if args.check or args.dry_run:
            print(f"{prof.name}: MISSING {', '.join(gone)}  (hook file present, not registered)")
            continue
        repair(settings)
        print(f"{prof.name}: RESTORED {', '.join(gone)}")

    if args.check and damaged:
        print(f"\n{damaged} profile(s) have lost an operator-owned control. This tool removed it; "
              "run without --check to put it back.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
