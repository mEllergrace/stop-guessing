"""Where this toolchain's DATA lives — project-local by default, never the agent's config dir.

The defect this fixes, found by the operator: every path for evidence resolved under
`$CLAUDE_CONFIG_DIR` (e.g. `~/.claude-ies/stop-guessing/`). That directory belongs to the agent and
is shared by every session and every project running under that profile.

Measured before changing anything: **31 state files, ~24 of them real Claude Code session UUIDs**,
pooled from whatever projects happened to be open. And the state records `session_id` with no `cwd`
and no project, so there is no way even in principle to attribute any of them. A provenance tool had
produced two dozen unattributable records and put them in someone else's directory.

Three rules, in order:

1. **Default to the directory the tool is called from** — `./.stop-guessing/`. Evidence belongs
   beside the work it describes, one ledger per project, attributable by construction.
2. **The old location stays readable.** Accumulated evidence is not disposable state, so a legacy
   profile directory that already holds records is still found and reported. Nothing is orphaned and
   nothing is silently moved: moving evidence without recording it is precisely the ISO 27037 §5.4.1
   alteration this project refuses to make.
3. **The choice stays open.** `$STOP_GUESSING_HOME` overrides, so a deployment that genuinely wants
   one shared ledger — a single-project machine, or a central collector — can still have it. The
   default changed; the option did not close.

`stop-guessing.json` is deliberately NOT moved. That is *configuration* (which posture applies), and
a profile-level config layer is correct and intended. The objection was to data, not settings.
"""

from __future__ import annotations

import os
from pathlib import Path

DIRNAME = ".stop-guessing"

#: Subdirectory names, so every caller agrees on the layout.
LEDGER = "ledger"
STATE = "state"
LOCKS = "locks"


def project_home(cwd: str | os.PathLike | None = None) -> Path:
    """The default: `<cwd>/.stop-guessing`."""
    return Path(cwd or Path.cwd()) / DIRNAME


def legacy_home(config_dir: str | os.PathLike | None = None) -> Path:
    """Where data used to go. Read-only as far as new writes are concerned."""
    cfg = config_dir or os.environ.get("CLAUDE_CONFIG_DIR") or (Path.home() / ".claude")
    return Path(cfg) / "stop-guessing"


def data_home(cwd: str | os.PathLike | None = None,
              config_dir: str | os.PathLike | None = None) -> Path:
    """Where data is WRITTEN. `$STOP_GUESSING_HOME` wins, else project-local.

    Deliberately does not fall back to the legacy location for writes, even when it exists. A tool
    that keeps writing to the old place because the old place is there never actually migrates, and
    the operator's instruction was that this data does not belong in the agent's directory.
    """
    override = os.environ.get("STOP_GUESSING_HOME")
    if override:
        return Path(override).expanduser()
    return project_home(cwd)


def ledger_file(cwd=None, config_dir=None) -> Path:
    return data_home(cwd, config_dir) / LEDGER / "custody.jsonl"


def state_dir(cwd=None, config_dir=None) -> Path:
    return data_home(cwd, config_dir) / STATE


def locks_dir(cwd=None, config_dir=None) -> Path:
    return data_home(cwd, config_dir) / LOCKS


def legacy_data_found(config_dir=None) -> dict:
    """What the old profile location still holds, so it can be reported rather than abandoned."""
    home = legacy_home(config_dir)
    led = home / LEDGER / "custody.jsonl"
    states = sorted((home / STATE).glob("*.json")) if (home / STATE).is_dir() else []
    return {
        "home": str(home),
        "exists": home.is_dir(),
        "ledger": str(led) if led.is_file() else None,
        "ledger_records": sum(1 for _ in led.open(encoding="utf-8")) if led.is_file() else 0,
        "state_files": len(states),
        "note": ("Still readable and still counted. Not moved automatically: relocating evidence "
                 "without recording the move is exactly the ISO 27037 §5.4.1 alteration this "
                 "project refuses to perform silently."),
    }
