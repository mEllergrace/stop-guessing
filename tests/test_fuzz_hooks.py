"""Hostile payloads into both hooks.

A PreToolUse hook is on the critical path of every tool call. Three ways it can fail badly:

1. **Crash** — exit non-zero or spew a traceback, which in the worst case blocks the tool.
2. **Emit garbage** — non-JSON on stdout, which the host must then interpret.
3. **Fail open silently** — swallow the input and record nothing, so enforcement and evidence are
   both lost with no trace. This is the subtle one, and it is what #23 was about.

So the contract under fuzz is: exit 0, stdout is empty or valid JSON, no traceback, and any
internal failure leaves a `recorder.selfcheck` record behind.

Payloads are built in Python rather than shell so control characters, lone surrogates and
100 KB commands can be expressed exactly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from stop_guessing.version import repo_root

HOOKS = ("hook_gate", "hook_post")


def _payloads() -> dict[str, bytes]:
    long_path = "/tmp/" + "a" * 8000 + ".csv"
    return {
        "empty": b"",
        "whitespace": b"   \n\t ",
        "not-json": b"hello world",
        "json-array": b"[1,2,3]",
        "json-string": b'"just a string"',
        "json-null": b"null",
        "empty-object": b"{}",
        "null-tool-name": json.dumps(
            {"tool_name": None, "tool_input": {}, "session_id": "f"}).encode(),
        "tool-input-string": json.dumps(
            {"tool_name": "Read", "tool_input": "nope", "session_id": "f"}).encode(),
        "tool-input-null": json.dumps(
            {"tool_name": "Read", "tool_input": None, "session_id": "f"}).encode(),
        "no-session-id": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x.csv"}}).encode(),
        "session-traversal": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x.csv"},
             "session_id": "../../../etc/passwd"}).encode(),
        "session-absolute": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x.csv"},
             "session_id": "/etc/shadow"}).encode(),
        "session-int": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x.csv"},
             "session_id": 10 ** 60}).encode(),
        "path-newline": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/a\nb.csv"},
             "session_id": "f"}).encode(),
        "path-8k": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": long_path},
             "session_id": "f"}).encode(),
        "path-unicode": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/客户名单.csv"},
             "session_id": "f"}).encode(),
        "path-list": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": ["/tmp/a", "/tmp/b"]},
             "session_id": "f"}).encode(),
        "path-dict": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": {"a": 1}},
             "session_id": "f"}).encode(),
        "command-100k": json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "cat " + ("x.csv " * 15000)},
             "session_id": "f"}).encode(),
        # A literal NUL in this source file makes the file itself unparseable, so it is built.
        "command-null-byte": json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "cat a" + chr(0) + "b.csv"},
             "session_id": "f"}).encode(),
        "raw-null-in-json": b'{"tool_name":"Bash","tool_input":{"command":"cat a'
                            + bytes([0]) + b'b.csv"},"session_id":"f"}',
        "deep-nesting": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x.csv"},
             "session_id": "f", "x": [[[[[[[[[[1]]]]]]]]]]}).encode(),
        "lone-surrogate": b'{"tool_name":"Read","tool_input":{"file_path":"/tmp/\\ud800.csv"},'
                          b'"session_id":"f"}',
        "invalid-utf8": b'{"tool_name":"Read","tool_input":{"file_path":"/tmp/\xff\xfe.csv"},'
                        b'"session_id":"f"}',
        "tool-result-string": json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x.csv"},
             "session_id": "f", "tool_result": "boom"}).encode(),
        "tool-result-list": json.dumps(
            {"tool_name": "Write", "tool_input": {"file_path": "/tmp/x.csv"},
             "session_id": "f", "tool_result": [1, 2]}).encode(),
        "unknown-tool": json.dumps(
            {"tool_name": "SomethingNobodyDefined", "tool_input": {"x": 1},
             "session_id": "f"}).encode(),
        "credential-relative": json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "cat api_keys.txt"},
             "session_id": "f"}).encode(),
    }


def _run(mod: str, payload: bytes, config_dir: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "CLAUDE_CONFIG_DIR": config_dir}
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", f"stop_guessing.cli.{mod}"],
        input=payload, capture_output=True, cwd=str(repo_root()), env=env, timeout=180,
    )


@pytest.mark.slow
@pytest.mark.parametrize("hook", HOOKS)
@pytest.mark.parametrize("name", sorted(_payloads()))
def test_hostile_payload_is_survivable(hook, name, tmp_path):
    """Exit 0, no traceback, and stdout is empty or valid JSON."""
    res = _run(hook, _payloads()[name], str(tmp_path / "claude"))

    assert res.returncode == 0, (
        f"{hook} exited {res.returncode} on {name!r}; a hook on the critical path of every tool "
        f"call must not fail: {res.stderr.decode('utf-8', 'replace')[-400:]}"
    )
    assert b"Traceback" not in res.stderr, (
        f"{hook} printed a traceback on {name!r}: "
        f"{res.stderr.decode('utf-8', 'replace')[-400:]}"
    )
    out = res.stdout.decode("utf-8", "replace").strip()
    if out:
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError as exc:
            pytest.fail(f"{hook} emitted non-JSON on {name!r}: {exc}; first 200 chars: {out[:200]}")
        assert isinstance(parsed, dict)
        if "hookSpecificOutput" in parsed:
            assert parsed["hookSpecificOutput"]["permissionDecision"] in (
                "allow", "deny", "ask", "defer")


@pytest.mark.slow
@pytest.mark.parametrize("hook", HOOKS)
def test_session_id_cannot_escape_the_state_directory(hook, tmp_path):
    """A traversal or absolute session id must not write outside the state dir.

    The session id comes from the host, but treating it as trusted would make it a path-injection
    primitive — `../../../etc/passwd` as a filename is the whole attack.
    """
    cfg = tmp_path / "claude"
    outside = tmp_path / "outside.json"
    for sid in ("../../../" + str(outside), "/etc/shadow", "..", "."):
        _run(hook, json.dumps({
            "tool_name": "Read", "tool_input": {"file_path": "/tmp/roster.csv"},
            "session_id": sid}).encode(), str(cfg))
    assert not outside.exists(), "a session id escaped the state directory"
    state_dir = cfg / "stop-guessing" / "state"
    if state_dir.exists():
        for p in state_dir.iterdir():
            assert p.parent == state_dir, f"{p} is outside the state directory"


@pytest.mark.slow
def test_internal_failure_leaves_a_selfcheck_record(tmp_path, monkeypatch):
    """#23: a crashed gate must record the gap, not vanish.

    Forced by pointing the policy directory at nothing, which makes the decision path raise.
    """
    from stop_guessing.cli import hook_gate

    cfg = tmp_path / "claude"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    # 0.6.1: the gate writes project-local now, so point the data home at this profile's
    # shape — these assert the gate's WRITE behaviour, not the default location, which
    # tests/test_data_location.py and test_the_gate_never_writes_to_the_config_dir own.
    monkeypatch.setenv("STOP_GUESSING_HOME", str(cfg / "stop-guessing"))
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", "fuzz-key-" + "x" * 24)
    hook_gate._record_gap(
        {"tool_name": "Read", "tool_input": {"file_path": "/tmp/roster.csv"},
         "session_id": "gapcheck"},
        RuntimeError("forced for the test"),
    )

    ledger = cfg / "stop-guessing" / "ledger" / "custody.jsonl"
    assert ledger.is_file(), "no gap record was written"
    recs = [json.loads(x) for x in ledger.read_text().splitlines()]
    gaps = [r for r in recs if r.get("op") == "recorder.selfcheck"]
    assert gaps, "a gate failure left no recorder.selfcheck record"
    assert gaps[-1]["severity"] == "critical"
    assert "failed open" in gaps[-1]["enforcement"]
