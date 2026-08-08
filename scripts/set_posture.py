#!/usr/bin/env python3
# build-ok: searched scripts/ and install.sh. repair_operator_rules.py is the closest match and was
# read in full — it writes live profile settings.json to restore HOOK REGISTRATIONS, and has no
# concept of posture or of stop-guessing.json; extending it would mean bolting an unrelated config
# key onto a tool whose whole docstring is about #87. install.sh registers hooks and never writes a
# posture. hook_gate.posture_source() READS the chain and deliberately does not write ("choosing the
# posture is the operator's", cmd_ops.py:107). audit_verify.py touches profiles only to audit them.
# Nothing sets a posture, so this is new rather than a duplicate. Layout, backup discipline, atomic
# replace and the --check/--profile/--all-profiles interface are taken from repair_operator_rules.py.
"""Set the STOP-GUESSING posture in a profile's config, or report what each profile resolves to.

The operator hit this: the shipped default moved to `observe` in v0.5.2, but the personal profile
kept asking for approval. A default is the LAST layer `resolve_posture` consults, so it only applies
where nothing above it has spoken — and every layer but the project one is keyed on
`$CLAUDE_CONFIG_DIR`. `~/.claude` and `~/.claude-ies` therefore resolve independently, and changing
the shipped default does not disturb an explicit `steer` already written into either one.

Writing the posture EXPLICITLY is also version-robust in a way that relying on the default is not:
a profile running an older installed plugin (< v0.5.2, where the built-in default was still `steer`)
honours layer 3 exactly the same way, so an explicit `observe` fixes it without an upgrade.

    python3 scripts/set_posture.py --check                        # what each profile resolves to
    python3 scripts/set_posture.py --profile ~/.claude observe    # set one profile
    python3 scripts/set_posture.py --all-profiles observe         # set every ~/.claude*

Three rules this follows, all of them the repo's own:

1. **Read-modify-write, never overwrite** (`custody-options.md`): other keys in `stop-guessing.json`
   belong to no-noodles (`no_ad_hoc_probes`, `check_before_build`, `risk_scoring`) or to the
   operator, and are preserved byte-for-byte in value.
2. **Report the managed floor rather than fight it.** `managed.json` sits above every layer and may
   only be tightened. If a floor would override the value being written, this says so and does not
   pretend the write took effect. It never edits `managed.json` — that file exists precisely so the
   recorded party cannot weaken its own policy (#47).
3. **Nothing is removed.** The legacy `.state` file is reported, never deleted; layer 3 already wins
   over it, and deleting an operator's file to make a config resolve is not this tool's call.
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

from stop_guessing.cli.hook_gate import (  # noqa: E402
    DEFAULT_POSTURE,
    POSTURE_ORDER,
    resolve_posture,
)

CONFIG = "stop-guessing.json"
MANAGED = "managed.json"
LEGACY = "stop-guessing.state"


def _read_json(path: Path) -> dict:
    """Missing or unparseable both mean "this layer says nothing", matching the resolver."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def managed_floor(profile: Path) -> str | None:
    v = _read_json(profile / MANAGED).get("posture")
    return v if v in POSTURE_ORDER else None


def legacy_value(profile: Path) -> str | None:
    try:
        v = (profile / LEGACY).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return v if v in POSTURE_ORDER else None


def inspect(profile: Path) -> dict:
    """What this profile resolves to and which layer says what. Reads only.

    `resolve_posture` is called with `cwd=None` on purpose: passing a cwd would fold in whatever
    project happens to be open and report a per-project answer as if it were the profile's.
    """
    return {
        "profile": profile,
        "configured": (lambda v: v if v in POSTURE_ORDER else None)(
            _read_json(profile / CONFIG).get("posture")),
        "managed": managed_floor(profile),
        "legacy": legacy_value(profile),
        "effective": _effective(profile),
    }


def _effective(profile: Path) -> str:
    """The resolver's own answer for this profile, not a reimplementation of it.

    `resolve_posture` reads `$CLAUDE_CONFIG_DIR`, so the variable is set around the call and
    restored afterwards. Duplicating the four-layer precedence here would be a second copy of the
    rule that could disagree with the gate — which is the class of defect this whole script exists
    to clean up.
    """
    import os

    before = os.environ.get("CLAUDE_CONFIG_DIR")
    os.environ["CLAUDE_CONFIG_DIR"] = str(profile)
    try:
        return resolve_posture(None)
    finally:
        if before is None:
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
        else:
            os.environ["CLAUDE_CONFIG_DIR"] = before


def set_posture(profile: Path, posture: str, dry_run: bool = False) -> dict:
    """Write `posture` into the profile's `stop-guessing.json`, preserving every other key."""
    if posture not in POSTURE_ORDER:
        raise ValueError(f"{posture!r} is not one of {POSTURE_ORDER}")

    path = profile / CONFIG
    data = _read_json(path)
    before = data.get("posture")
    result = {
        "profile": profile,
        "path": path,
        "before": before,
        "after": posture,
        "changed": before != posture,
        "preserved": sorted(k for k in data if k != "posture"),
        "managed": managed_floor(profile),
        "legacy": legacy_value(profile),
        "wrote": False,
    }
    if dry_run or not result["changed"]:
        return result

    data["posture"] = posture
    profile.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        shutil.copy2(path, path.with_suffix(f".json.bak-{time.strftime('%Y%m%dT%H%M%S')}"))
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)               # atomic: an interrupted write must not truncate the config
    result["wrote"] = True
    return result


def profiles(args) -> list[Path]:
    if args.profile:
        return [Path(p).expanduser() for p in args.profile]
    if args.all_profiles or args.check:
        return sorted(p for p in Path.home().glob(".claude*") if p.is_dir())
    return []


def _warn_floor(res: dict) -> bool:
    """A managed floor stronger than the requested posture means the write will not take effect."""
    floor = res["managed"]
    if not floor or POSTURE_ORDER.index(res["after"]) >= POSTURE_ORDER.index(floor):
        return False
    print(f"    NOT IN EFFECT: managed.json pins a floor of `{floor}`, which overrides "
          f"`{res['after']}`. That file is intentionally outside project write authority — change "
          f"it yourself at {res['profile'] / MANAGED} if the floor is no longer wanted.")
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("posture", nargs="?", choices=POSTURE_ORDER,
                    help=f"the posture to write (shipped default: {DEFAULT_POSTURE})")
    ap.add_argument("--profile", action="append", help="a CLAUDE_CONFIG_DIR (repeatable)")
    ap.add_argument("--all-profiles", action="store_true")
    ap.add_argument("--check", action="store_true", help="report only, write nothing")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    targets = profiles(args)
    if not targets:
        ap.error("give --profile, --all-profiles or --check")
    if not args.check and not args.posture:
        ap.error("a posture is required unless --check")

    blocked = 0
    for prof in targets:
        if args.check:
            i = inspect(prof)
            asks = "" if i["effective"] == DEFAULT_POSTURE else "   <- ASKS or DENIES on some calls"
            print(f"{prof}: effective `{i['effective']}`{asks}")
            for label, key, fname in (("config ", "configured", CONFIG),
                                      ("managed", "managed", MANAGED),
                                      ("legacy ", "legacy", LEGACY)):
                if i[key]:
                    print(f"    {label}: `{i[key]}`  ({prof / fname})")
            if not any(i[k] for k in ("configured", "managed", "legacy")):
                print(f"    nothing set — the shipped default `{DEFAULT_POSTURE}` applies")
            continue

        res = set_posture(prof, args.posture, dry_run=args.dry_run)
        verb = "would set" if args.dry_run else ("set" if res["wrote"] else "already")
        print(f"{prof}: {verb} posture `{res['after']}` (was "
              f"{('`' + res['before'] + '`') if res['before'] else 'unset'})  {res['path']}")
        if res["preserved"]:
            print(f"    preserved: {', '.join(res['preserved'])}")
        if res["legacy"]:
            print(f"    note: legacy {LEGACY} still says `{res['legacy']}`; the config above wins "
                  "over it and it has been left in place, not deleted.")
        blocked += _warn_floor(res)

    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
