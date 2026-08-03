"""Self-integrity: never let the recorded party control what the recorder depends on.

Berkeley RDI (April 2026) showed a zero-capability agent scoring ~100% on eight benchmarks by
attacking the *evaluator* rather than the task — including installing a fake `curl` wrapper that
returned fabricated success to the grader. The generalisation is the rule this module enforces:

    Anything the recorder resolves at runtime is something the recorded party can substitute.

So nothing is resolved at runtime. The binary is pinned by resolved absolute path *and* digest;
the hooks are pinned by digest; the ledger directory is mode-checked; and `PATH` is never used to
find anything. A `PATH` lookup is the single most available substitution point on the machine.

The checks report findings rather than raising. A guard that crashes on hostile input hands the
attacker "the tool errored" instead of "the recorder was tampered with".
"""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from stop_guessing.artifacts.digest import file_digest

MANIFEST_NAME = "install-manifest.json"


@dataclass
class GuardReport:
    ok: bool = True
    isolation_tier: int = 0
    findings: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)

    def fail(self, why: str) -> None:
        self.ok = False
        self.findings.append(why)

    def note(self, what: str) -> None:
        self.checked.append(what)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "isolation_tier": self.isolation_tier,
                "findings": list(self.findings), "checked": list(self.checked)}


def resolve_self(argv0: str) -> Path:
    """The real path of the running binary. `realpath`, never a `PATH` search."""
    return Path(argv0).resolve()


def check_not_path_resolved(name: str, expected: Path) -> str | None:
    """Is the first `name` on PATH something other than the pinned binary?

    Finding a *different* executable earlier on PATH is the fake-`curl` attack exactly.
    """
    found = shutil.which(name)
    if found is None:
        return None
    if Path(found).resolve() != expected.resolve():
        return (f"PATH resolves {name!r} to {found} but the pinned binary is {expected} — "
                "a shadowing executable is earlier on PATH")
    return None


def check_manifest(manifest: dict, root: Path) -> list[str]:
    """Every pinned file must still hash to what it hashed to at install."""
    findings = []
    for rel, expected in sorted(manifest.get("files", {}).items()):
        actual = file_digest(root / rel)
        if actual is None:
            findings.append(f"{rel} is missing — a pinned component was removed")
        elif actual != expected:
            findings.append(
                f"{rel} digest changed (pinned {expected[:16]}…, now {actual[:16]}…) — "
                "a pinned component was substituted"
            )
    return findings


def check_ledger_dir(path: Path) -> list[str]:
    """The ledger directory must not be writable by anyone but its owner."""
    findings = []
    if not path.exists():
        return findings
    mode = path.stat().st_mode
    if mode & stat.S_IWOTH:
        findings.append(f"{path} is world-writable ({stat.filemode(mode)})")
    if mode & stat.S_IWGRP and (path.stat().st_gid == os.getgid()):
        findings.append(
            f"{path} is group-writable by the running user's own group ({stat.filemode(mode)}) — "
            "at isolation tier 2 the ledger group must not be the agent's group"
        )
    return findings


def check_registration(settings: dict, pinned_command: str) -> list[str]:
    """The hook registration must point at the pinned absolute path.

    A literal `~` expands at hook-execution time under whatever HOME is then set, which is both a
    real incident in this estate (2026-07-16) and a substitution point.
    """
    findings = []
    hooks = settings.get("hooks", {}).get("PreToolUse", [])
    commands = [h.get("command", "") for group in hooks for h in group.get("hooks", [])]
    ours = [c for c in commands if "stop-guessing" in c or "coc_gate" in c]
    if not ours:
        findings.append("no STOP-GUESSING PreToolUse registration found")
        return findings
    for c in ours:
        if c.strip() != pinned_command.strip():
            findings.append(f"registration {c!r} does not match the pinned {pinned_command!r}")
        if "~" in c:
            findings.append(f"registration {c!r} contains a literal ~, which expands at run time")
    return findings


def isolation_tier(*, daemon_running: bool, separate_uid: bool, remote: bool = False) -> int:
    """Report the tier honestly. Tier 0 is a fallback, never silent."""
    if remote:
        return 3
    if daemon_running and separate_uid:
        return 2
    if daemon_running:
        return 1
    return 0


def self_check(
    *,
    argv0: str,
    manifest: dict | None = None,
    root: Path | None = None,
    ledger_dir: Path | None = None,
    settings: dict | None = None,
    pinned_command: str = "",
    daemon_running: bool = False,
    separate_uid: bool = False,
) -> GuardReport:
    """Everything checked in one pass, at session start and before any keyed write."""
    rep = GuardReport()
    me = resolve_self(argv0)
    rep.note(f"self resolved to {me}")

    if manifest:
        pinned = manifest.get("binary_digest")
        actual = file_digest(me)
        if pinned and actual != pinned:
            rep.fail(f"the running binary's digest {str(actual)[:16]}… does not match the pinned "
                     f"{pinned[:16]}… — the recorder itself was substituted")
        else:
            rep.note("binary digest matches the install manifest")
        for f in check_manifest(manifest, root or me.parent):
            rep.fail(f)
        rep.note(f"{len(manifest.get('files', {}))} pinned component(s) checked")

    for name in ("stop-guessing", "coc"):
        finding = check_not_path_resolved(name, me)
        if finding:
            rep.fail(finding)
    rep.note("PATH shadowing checked for stop-guessing, coc")

    if ledger_dir:
        for f in check_ledger_dir(ledger_dir):
            rep.fail(f)
        rep.note(f"ledger directory permissions checked ({ledger_dir})")

    if settings is not None and pinned_command:
        for f in check_registration(settings, pinned_command):
            rep.fail(f)
        rep.note("hook registration checked against the pinned absolute path")

    rep.isolation_tier = isolation_tier(daemon_running=daemon_running, separate_uid=separate_uid)
    if rep.isolation_tier == 0:
        rep.note("isolation tier 0 — in-process fallback; recorded, never silent")
    return rep


def build_manifest(binary: Path, files: dict[str, Path]) -> dict:
    return {
        "binary": str(binary),
        "binary_digest": file_digest(binary),
        "files": {rel: file_digest(p) for rel, p in files.items()},
    }
