"""The default posture must never seek permission — the operator's constraint, as a test.

Recorded from the outset: *"you must respect the permissions that are already set. This is not
meant to block anything or seek permissions. It is for logging Chain of Custody and data provenance
to show evidence."*

`observe` is the default and this is what makes that promise mechanical. The one documented
exception is a write to the ledger itself, refused under every posture — that protects the evidence
rather than policing the operator, and `{"protect_ledger": false}` turns even that off.

`steer` and `bar` are opt-in and DO ask; that is their documented purpose and this file does not
touch them. The point is that nobody arrives at an asking gate by installing the tool.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from stop_guessing.version import repo_root

CLI = [sys.executable, "-m", "stop_guessing.cli.hook_gate"]

CASES = [
    ("a classified read", {"tool_name": "Read",
                           "tool_input": {"file_path": "/example/work/CSA/roster.csv"}}),
    ("an ordinary read", {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}),
    ("a benign bash", {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}),
    ("an egress", {"tool_name": "Bash",
                   "tool_input": {"command": "scp ./x.csv user@host:/tmp/"}}),
    ("a write", {"tool_name": "Write",
                 "tool_input": {"file_path": "/tmp/sg-observe/out.txt", "content": "x"}}),
]


def _run(body, cwd):
    env = dict(os.environ)
    env["CLAUDE_CONFIG_DIR"] = cwd            # hermetic: no profile config, so the DEFAULT applies
    return subprocess.run(  # noqa: S603
        CLI, input=json.dumps(body).encode("utf-8"),
        capture_output=True, cwd=str(repo_root()), timeout=300, env=env)


def _decision(out: str):
    out = out.strip()
    if not out:
        return None
    try:
        hso = (json.loads(out).get("hookSpecificOutput") or {})
    except ValueError:
        return None
    return hso.get("permissionDecision")


def test_the_shipped_default_posture_is_observe(tmp_path):
    """If this ever flips, everything below becomes a test of something else."""
    from stop_guessing.cli.hook_gate import resolve_posture

    os.environ["CLAUDE_CONFIG_DIR"] = str(tmp_path)
    try:
        assert resolve_posture(str(tmp_path)) == "observe"
    finally:
        os.environ.pop("CLAUDE_CONFIG_DIR", None)


def test_observe_never_asks_and_never_denies_ordinary_work(tmp_path):
    """Installing the tool must not put a second permission gate in front of the operator."""
    offenders = []
    for name, body in CASES:
        payload = {"session_id": "sg-observe", "hook_event_name": "PreToolUse",
                   "tool_use_id": "toolu_obs", "cwd": str(tmp_path), **body}
        d = _decision(_run(payload, str(tmp_path)).stdout.decode())
        if d in ("ask", "deny"):
            offenders.append((name, d))
    assert not offenders, (
        f"the DEFAULT posture interrupted the operator: {offenders}. observe records and blocks "
        "nothing; a recorder that prompts is overriding the decision its user already made.")


def test_observe_never_grants_either(tmp_path):
    """The other half. Recording is not deciding, in either direction."""
    for name, body in CASES:
        payload = {"session_id": "sg-observe", "hook_event_name": "PreToolUse",
                   "tool_use_id": "toolu_obs", "permission_mode": "acceptEdits",
                   "cwd": str(tmp_path), **body}
        assert _decision(_run(payload, str(tmp_path)).stdout.decode()) != "allow", (
            f"{name}: the default posture auto-approved a call")


def test_the_ledger_is_still_protected_under_observe(tmp_path):
    """The documented exception, and the control: 'never blocks' must not mean 'never protects'.

    Without this, `test_observe_never_asks…` would be satisfied by a gate that has no opinions at
    all, which is indistinguishable from a broken one.
    """
    ledger = tmp_path / "stop-guessing" / "ledger" / "custody.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    payload = {"session_id": "sg-observe", "hook_event_name": "PreToolUse",
               "tool_use_id": "toolu_obs", "cwd": str(tmp_path),
               "tool_name": "Write",
               "tool_input": {"file_path": str(ledger), "content": "forged"}}
    assert _decision(_run(payload, str(tmp_path)).stdout.decode()) == "deny", (
        "a write to the evidence ledger was not refused under observe — the one thing that must be")
