"""Replay corpus cases through the vendored hooks and capture what they actually do.

Two properties this module must hold, both learned from no-noodles' own test suite:

- **Hermetic.** Every replay gets a fresh ``CLAUDE_CONFIG_DIR`` under a temp root. no-noodles'
  tests previously wrote shape counters into the developer's real config dir and then passed or
  failed based on unrelated prior activity. A compatibility gate with that flaw would be worse
  than no gate.
- **Observed, not asserted.** The golden file records what the hooks *did*, byte for byte. It is
  not a list of what someone believed they should do. When upstream behaviour changes, the diff
  is the finding.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from stop_guessing.compat.corpus import Case

HOOK_ORDER = [
    "check_credentials.sh",
    "no_noodle.sh",
    "check_before_build.sh",
    "risk_gate.sh",
]


def vendored_dir() -> Path:
    return Path(__file__).resolve().parent / "nonoodles"


@dataclass(frozen=True)
class Outcome:
    """What one hook did with one payload."""

    case_id: str
    hook: str
    exit_code: int
    stdout: str
    stderr: str

    def key(self) -> str:
        return f"{self.case_id}::{self.hook}"


def _seed_config_dir(tmp: Path) -> Path:
    """A hermetic CLAUDE_CONFIG_DIR containing the vendored hooks and libs."""
    cfg = tmp / "claude"
    hooks = cfg / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    src = vendored_dir()
    for f in src.iterdir():
        # not is_file(): an installed runtime grows a __pycache__ directory in
        # here, and copy2 on a directory raises IsADirectoryError — which took
        # out the whole acceptance gate for superseding no-noodles, at exactly
        # the moment the gate is what you want to trust.
        if f.name == "UPSTREAM_VERSION" or not f.is_file():
            continue
        shutil.copy2(f, hooks / f.name)
        if f.suffix == ".sh":
            (hooks / f.name).chmod(0o755)
    return cfg


def _seed_project(tmp: Path, cwd: str) -> Path:
    """A real directory for the case's cwd, with a .git so the hooks' repo-root walk terminates."""
    proj = tmp / "proj" / Path(cwd).name
    (proj / ".git").mkdir(parents=True, exist_ok=True)
    (proj / "scripts").mkdir(exist_ok=True)
    (proj / "workflows").mkdir(exist_ok=True)
    return proj


def run_case(case: Case, hooks: list[str] | None = None) -> list[Outcome]:
    """Run one case through each hook in a fresh hermetic environment.

    ``case.repeat`` runs happen inside the *same* config dir so frequency semantics are exercised;
    only the final run's outcome is recorded, because that is the one a user would experience.
    """
    hooks = hooks or HOOK_ORDER
    outcomes: list[Outcome] = []

    with tempfile.TemporaryDirectory(prefix="sg-replay-") as td:
        tmp = Path(td)
        cfg = _seed_config_dir(tmp)
        proj = _seed_project(tmp, case.cwd)

        payload = case.payload()
        # Rewrite corpus paths onto the hermetic project so the hooks see real directories.
        if case.tool in ("Write", "Read", "Edit"):
            fp = payload["tool_input"].get("file_path")
            if isinstance(fp, str):
                payload["tool_input"]["file_path"] = (
                    fp.replace("/tmp/sg-corpus/project-a", str(proj))
                    .replace("/tmp/sg-corpus/project-b", str(proj))
                )
        payload["cwd"] = str(proj)
        raw = json.dumps(payload).encode()

        env = dict(os.environ)
        env["CLAUDE_CONFIG_DIR"] = str(cfg)
        env["HOME"] = str(tmp / "home")
        (tmp / "home" / ".claude").mkdir(parents=True, exist_ok=True)
        env.update(case.env)

        for hook in hooks:
            hook_path = cfg / "hooks" / hook
            if not hook_path.exists():
                continue
            last = None
            for _ in range(case.repeat):
                last = subprocess.run(  # noqa: S603
                    ["bash", str(hook_path)],
                    input=raw,
                    capture_output=True,
                    cwd=str(proj),
                    env=env,
                    # Batch budget, not the production one: a corpus replay runs
                    # hundreds of hooks under contention (#91).
                    timeout=300,
                )
            assert last is not None
            outcomes.append(
                Outcome(
                    case_id=case.id,
                    hook=hook,
                    exit_code=last.returncode,
                    stdout=last.stdout.decode("utf-8", "replace"),
                    stderr=last.stderr.decode("utf-8", "replace"),
                )
            )
    return outcomes


def replay_all(cases: list[Case]) -> list[Outcome]:
    out: list[Outcome] = []
    for case in cases:
        out.extend(run_case(case))
    return out


def normalise(outcomes: list[Outcome]) -> dict:
    """Golden-file shape: stable ordering, temp paths scrubbed.

    Absolute temp paths differ every run, so they are replaced with a token. Nothing else is
    touched — a golden that "cleans up" real output stops being evidence.
    """
    import re

    tmp_re = re.compile(r"/(?:private/)?(?:tmp|var/folders)[^\s\"']*sg-replay-[^\s\"']*")
    rows = {}
    for o in sorted(outcomes, key=lambda x: (x.case_id, x.hook)):
        rows[o.key()] = {
            "exit_code": o.exit_code,
            "stdout": tmp_re.sub("<TMP>", o.stdout),
            "stderr": tmp_re.sub("<TMP>", o.stderr),
        }
    return rows


def summarise(outcomes: list[Outcome]) -> dict:
    blocked = [o.key() for o in outcomes if o.exit_code == 2]
    other = [o.key() for o in outcomes if o.exit_code not in (0, 2)]
    return {
        "invocations": len(outcomes),
        "cases": len({o.case_id for o in outcomes}),
        "blocked": len(blocked),
        "blocked_keys": sorted(blocked),
        "unexpected_exit": sorted(other),
    }


def outcome_dicts(outcomes: list[Outcome]) -> list[dict]:
    return [asdict(o) for o in outcomes]
