"""`{"record": false}` — switching recording off for ONE project.

The only off switch was `$STOP_GUESSING_DISABLE`, which silences the recorder everywhere. An
operator who wanted a single project to stop being recorded — this repository recording itself,
most obviously — had no way to say so, and the nearest available control was a global one.

Reaching for a machine-wide switch to serve a per-project intent is how this gets done wrong, so
the option now exists at the layer the intent lives at.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from stop_guessing.cli.hook_gate import recording_disabled_for
from stop_guessing.version import repo_root

CLI = [sys.executable, "-m", "stop_guessing.cli.hook_gate"]


def _write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _run(module, body, cfg, cwd):
    env = dict(os.environ)
    env["CLAUDE_CONFIG_DIR"] = str(cfg)
    env.pop("STOP_GUESSING_DISABLE", None)
    # The suite-wide isolation in conftest points the data home at a shared tmp dir, which is right
    # for tests that only need a clean ledger. This one asserts WHERE a disabled project writes its
    # marker, so it needs the real project-local resolution the override would mask.
    env.pop("STOP_GUESSING_HOME", None)
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", module], input=json.dumps(body).encode("utf-8"),
        capture_output=True, cwd=str(repo_root()), timeout=300, env=env)


def test_absent_means_recording_stays_on(tmp_path):
    """The default must not change for anything that exists today."""
    assert recording_disabled_for(str(tmp_path)) is False


def test_a_project_can_switch_its_own_recording_off(tmp_path):
    _write(tmp_path / ".stop-guessing.json", {"record": False})
    assert recording_disabled_for(str(tmp_path)) is True


def test_record_true_is_explicitly_on(tmp_path):
    _write(tmp_path / ".stop-guessing.json", {"record": True})
    assert recording_disabled_for(str(tmp_path)) is False


def test_the_project_layer_beats_the_profile(tmp_path, monkeypatch):
    """Same precedence as `posture`: project first, profile as the default under it."""
    cfg = tmp_path / "claude"
    _write(cfg / "stop-guessing.json", {"record": False})
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    _write(tmp_path / ".stop-guessing.json", {"record": True})
    assert recording_disabled_for(str(tmp_path)) is False


def test_a_profile_default_applies_where_a_project_says_nothing(tmp_path, monkeypatch):
    cfg = tmp_path / "claude"
    _write(cfg / "stop-guessing.json", {"record": False})
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    assert recording_disabled_for(str(tmp_path)) is True


def test_a_managed_floor_overrides_the_switch(tmp_path, monkeypatch):
    """#47: the recorded party must not be able to weaken the policy it is recorded under.

    This key would be the cleanest possible lever for exactly that — a project writing one line to
    stop being recorded at all — so a managed floor keeps recording on regardless.
    """
    cfg = tmp_path / "claude"
    _write(cfg / "managed.json", {"posture": "steer"})
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    _write(tmp_path / ".stop-guessing.json", {"record": False})
    assert recording_disabled_for(str(tmp_path)) is False


def test_a_non_boolean_is_ignored_rather_than_guessed(tmp_path):
    _write(tmp_path / ".stop-guessing.json", {"record": "no"})
    assert recording_disabled_for(str(tmp_path)) is False


def test_unparseable_config_does_not_switch_recording_off(tmp_path):
    """Failing OPEN here means recording continues, which is the safe direction for a recorder."""
    (tmp_path / ".stop-guessing.json").write_text("{not json", encoding="utf-8")
    assert recording_disabled_for(str(tmp_path)) is False


def test_the_switch_preserves_the_posture_key_beside_it(tmp_path):
    from stop_guessing.cli.hook_gate import resolve_posture

    _write(tmp_path / ".stop-guessing.json", {"posture": "steer", "record": False})
    assert recording_disabled_for(str(tmp_path)) is True
    assert resolve_posture(str(tmp_path)) == "steer"


# ── every hook honours it, not just the gate ────────────────────────────────


def test_the_gate_records_a_marker_and_then_stops(tmp_path):
    """Absence of records must never read as absence of activity (#83, same failure mode)."""
    cfg = tmp_path / "claude"
    cfg.mkdir(parents=True, exist_ok=True)
    _write(tmp_path / ".stop-guessing.json", {"record": False})
    body = {"session_id": "s-off", "hook_event_name": "PreToolUse", "tool_use_id": "t1",
            "cwd": str(tmp_path), "tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}
    res = _run("stop_guessing.cli.hook_gate", body, cfg, tmp_path)
    assert res.returncode == 0
    assert res.stdout.decode().strip() == "", "a disabled project must not emit a decision"

    ledger = tmp_path / ".stop-guessing" / "ledger" / "custody.jsonl"
    assert ledger.is_file(), "the transition was not recorded; silence would be indistinguishable"
    entries = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines() if x.strip()]
    detail = " ".join(str((e.get("predicate", e)).get("detail")) for e in entries)
    assert "DISABLED for this project" in detail


def test_post_and_lifecycle_hooks_honour_it_too(tmp_path):
    """A switch that silenced only the gate would leave the loudest half still writing."""
    cfg = tmp_path / "claude"
    cfg.mkdir(parents=True, exist_ok=True)
    _write(tmp_path / ".stop-guessing.json", {"record": False})
    target = tmp_path / "out.txt"
    target.write_text("x", encoding="utf-8")

    post = {"session_id": "s-off", "hook_event_name": "PostToolUse", "tool_use_id": "t2",
            "cwd": str(tmp_path), "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": "x"},
            "tool_response": {"success": True}}
    assert _run("stop_guessing.cli.hook_post", post, cfg, tmp_path).returncode == 0

    life = {"session_id": "s-off", "hook_event_name": "UserPromptSubmit",
            "cwd": str(tmp_path), "prompt": "/custody"}
    assert _run("stop_guessing.cli.hook_lifecycle", life, cfg, tmp_path).returncode == 0

    ledger = tmp_path / ".stop-guessing" / "ledger" / "custody.jsonl"
    entries = ([json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines() if x.strip()]
               if ledger.is_file() else [])
    ops = {(e.get("predicate", e)).get("op") for e in entries}
    assert ops <= {"recorder.selfcheck"}, f"a disabled project still recorded: {ops}"
