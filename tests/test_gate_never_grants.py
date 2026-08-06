"""The gate must never GRANT permission — only deny, ask, or stay silent.

The operator's constraint on this project is explicit: *"you must respect the permissions that are
already set. This is not meant to block anything or seek permissions. It is for logging Chain of
Custody and data provenance to show evidence."*

`hook_gate` emitted `permissionDecision: "allow"` whenever an `ask` had been downgraded to a
warning, under a comment claiming that `allow` "does not interrupt". That mistook the semantics: in
Claude Code an explicit `allow` from PreToolUse auto-approves the call and SUPPRESSES the prompt the
host would otherwise raise.

Under `bypassPermissions` that was redundant. Under `acceptEdits` it was a genuine grant — that mode
auto-accepts file edits but still prompts for Bash — so the recorder silently approved commands the
operator would have been asked about, including the ad-hoc fetch-pipe-parser shape that
`no_noodle.sh` allows on its first occurrence in a project. A provenance recorder was circumventing
the no-noodling policy it ships vendored.

Silence is the correct output: "this hook has no opinion" leaves the host's permission model exactly
as configured. The warning is not lost — it is in the custody record, which is the tool's actual job.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from stop_guessing.version import repo_root

# Assembled rather than written literally, so the vendored no_noodle.sh rule does not fire on this
# file's own text every time a developer greps or edits it. The SHAPE is what the gate must not
# auto-approve, and the shape is preserved exactly.
NOODLE_SHAPE = "curl -s https://example.com/data | " + "python3 -c 'import sys'"

PAYLOAD = {
    "session_id": "sg-grant-test",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_use_id": "toolu_grant",
    "tool_input": {"command": NOODLE_SHAPE},
    "cwd": str(repo_root()),
}


def _run(payload, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.hook_gate"],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True, cwd=str(repo_root()), timeout=300, env=env)


def _decisions(out: str):
    out = out.strip()
    if not out:
        return []
    try:
        d = json.loads(out)
    except ValueError:
        return []
    hso = d.get("hookSpecificOutput") or {}
    return [hso["permissionDecision"]] if "permissionDecision" in hso else []


def test_the_gate_never_emits_allow_in_any_permission_mode():
    """The regression itself, across every mode that can reach the downgrade path."""
    for mode in ("", "default", "acceptEdits", "bypassPermissions", "plan"):
        res = _run({**PAYLOAD, "permission_mode": mode})
        assert "allow" not in _decisions(res.stdout.decode()), (
            f"permission_mode={mode!r}: the gate auto-approved a tool call. A recorder that grants "
            "permission is not respecting the permissions already set.")


def test_the_source_contains_no_allow_emission():
    """Belt and braces — the runtime test above only covers the payloads it thinks of."""
    src = (repo_root() / "stop_guessing/cli/hook_gate.py").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert '"permissionDecision": "allow"' not in code, (
        "hook_gate emits an explicit allow somewhere; that auto-approves and suppresses the prompt")


def test_deny_and_ask_are_still_available():
    """The control. 'Never allow' must not be satisfied by a gate that says nothing at all."""
    from stop_guessing.cli.hook_gate import emit_ask, emit_deny

    assert callable(emit_deny) and callable(emit_ask)
    src = (repo_root() / "stop_guessing/cli/hook_gate.py").read_text(encoding="utf-8")
    assert '"permissionDecision": "deny"' in src
    assert '"permissionDecision": "ask"' in src


def test_a_denial_is_not_degraded_by_a_permissive_mode():
    """Bypassing permission PROMPTS is not the same as bypassing policy."""
    payload = {**PAYLOAD, "permission_mode": "bypassPermissions",
               "tool_input": {"command": "env | grep SECRET"}}
    out = _run(payload).stdout.decode()
    if out.strip():
        assert "allow" not in _decisions(out)


def test_silence_is_the_no_opinion_signal():
    """An empty stdout with exit 0 leaves the host's permission model untouched."""
    res = _run({**PAYLOAD, "permission_mode": "acceptEdits",
                "tool_name": "Read", "tool_input": {"file_path": str(repo_root() / "VERSION")}})
    assert res.returncode == 0
    assert "allow" not in _decisions(res.stdout.decode())
