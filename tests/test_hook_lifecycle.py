"""Session lifecycle hooks — SG-HARD-009/048/049 (#42, #81, #82).

Two of 31 documented events were registered, so the ledger was complete per tool call and silent
per session — no boundary, no prompt lineage, no compaction checkpoint, no reconciliation, and no
record at all of a tool call that failed.

Every test here asserts two things: the record is written, and the hook does not block. An observer
that can fail a session is an observer that gets uninstalled.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.cli import hook_lifecycle


@pytest.fixture
def profile(tmp_path, monkeypatch):
    """A hermetic CLAUDE_CONFIG_DIR with a real keyed ledger."""
    cfg = tmp_path / "claude"
    (cfg / "stop-guessing" / "ledger").mkdir(parents=True)
    key = cfg / "stop-guessing" / "chain.key"
    key.write_bytes(b"a-test-key-that-is-32-bytes-ok!!")
    key.chmod(0o600)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    monkeypatch.delenv("STOP_GUESSING_CHAIN_KEY", raising=False)
    return cfg


def _records(cfg):
    p = cfg / "stop-guessing" / "ledger" / "custody.jsonl"
    if not p.is_file():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _ops(cfg):
    return [r.get("op") for r in _records(cfg)]


# ── every event writes its record ────────────────────────────────────────────


def test_session_start_records_the_recorder_state_it_opened_with(profile):
    hook_lifecycle.session_start({"session_id": "s1", "source": "startup"})
    recs = _records(profile)
    assert "session.open" in _ops(profile)
    detail = json.loads(recs[-1]["detail"])
    assert "isolation_tier" in detail
    assert detail["source"] == "startup"


def test_session_start_flags_tier_zero_as_a_gap(profile):
    """No daemon means in-process writes, and that must be stated, not assumed."""
    hook_lifecycle.session_start({"session_id": "s1"})
    rec = _records(profile)[-1]
    assert any("tier 0" in g for g in rec["known_gaps"])
    assert rec["severity"] == "critical"


def test_prompt_submit_records_a_digest_and_never_the_prompt(profile):
    secret = "my password is hunter2 and the roster is at /work/CSA/roster.csv"
    hook_lifecycle.prompt_submit({"session_id": "s1", "prompt": secret})
    blob = json.dumps(_records(profile))
    assert "prompt.submit" in _ops(profile)
    assert "hunter2" not in blob, "the prompt text must never enter the ledger"
    assert "roster.csv" not in blob
    assert "sha256:" in blob


def test_failed_tool_calls_are_recorded(profile):
    """PostToolUse cannot see these: failures arrive on a different event entirely."""
    hook_lifecycle.tool_failed({"session_id": "s1", "tool_name": "Bash",
                                "tool_use_id": "toolu_1", "tool_error": "exit 127"})
    rec = _records(profile)[-1]
    assert rec["op"] == "tool.result"
    assert json.loads(rec["detail"])["success"] is False
    assert rec["severity"] == "warning"


def test_failed_tool_call_records_error_shape_not_error_text(profile):
    hook_lifecycle.tool_failed({"session_id": "s1", "tool_name": "Read",
                                "tool_use_id": "t", "tool_error": "/work/CSA/secret.csv missing"})
    assert "secret.csv" not in json.dumps(_records(profile))


def test_pre_compact_checkpoints_the_custody_digest(profile):
    hook_lifecycle.pre_compact({"session_id": "s1"})
    rec = _records(profile)[-1]
    assert rec["op"] == "custody.checkpoint"
    assert "session_custody_digest" in json.loads(rec["detail"])


def test_subagent_stop_records_a_merge(profile):
    hook_lifecycle.subagent_stop({"session_id": "s1", "agent_id": "sub-3"})
    rec = _records(profile)[-1]
    assert rec["op"] == "agent.merge"
    assert json.loads(rec["detail"])["child_agent"] == "sub-3"


def test_session_end_records_a_close(profile):
    hook_lifecycle.session_end({"session_id": "s1", "reason": "exit"})
    assert _ops(profile)[-1] == "session.close"


def test_stop_reconciles_and_records_the_result(profile):
    """The mechanism that catches a fabricated execution now actually runs."""
    hook_lifecycle.session_start({"session_id": "s1"})
    ref = hook_lifecycle.turn_stop({"session_id": "s1"})
    assert ref is not None
    rec = _records(profile)[-1]
    assert rec["op"] == "tool.reconcile"
    assert "dispatched" in json.loads(rec["detail"])


# ── none of them may block ───────────────────────────────────────────────────


@pytest.mark.parametrize("event", sorted(hook_lifecycle.HANDLERS))
def test_no_lifecycle_hook_ever_blocks(profile, event, monkeypatch, capsys):
    """Even when the handler raises, the exit code is 0."""
    monkeypatch.setattr(hook_lifecycle, "HANDLERS",
                        dict(hook_lifecycle.HANDLERS,
                             **{event: lambda p: (_ for _ in ()).throw(RuntimeError("boom"))}))
    monkeypatch.setattr("sys.stdin", type("S", (), {"buffer": type("B", (), {
        "read": staticmethod(lambda: json.dumps({"session_id": "s1"}).encode())})()})())
    assert hook_lifecycle.main([event]) == 0


def test_garbage_on_stdin_fails_open(profile, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("S", (), {"buffer": type("B", (), {
        "read": staticmethod(lambda: b"not json at all")})()})())
    assert hook_lifecycle.main(["SessionStart"]) == 0


def test_an_unknown_event_is_a_no_op(profile, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("S", (), {"buffer": type("B", (), {
        "read": staticmethod(lambda: b"{}")})()})())
    assert hook_lifecycle.main(["NotAnEvent"]) == 0
    assert _records(profile) == []


# ── registration must match implementation ───────────────────────────────────


def test_every_registered_event_has_a_handler():
    from stop_guessing.prove.runner import registered_hook_events

    registered = registered_hook_events()
    lifecycle = set(hook_lifecycle.HANDLERS)
    unhandled = registered - lifecycle - {"PreToolUse", "PostToolUse"}
    assert not unhandled, f"registered with no handler: {sorted(unhandled)}"


def test_every_handler_is_registered():
    """A handler nobody registers is the exact defect the audit found."""
    from stop_guessing.prove.runner import registered_hook_events

    missing = set(hook_lifecycle.HANDLERS) - registered_hook_events()
    assert not missing, f"implemented but not registered in hooks.json: {sorted(missing)}"


def test_the_claims_that_named_missing_hooks_can_now_resolve_them():
    """CLAIM-11/13/14 declared PreCompact, Stop and SessionStart."""
    from stop_guessing.prove.runner import registered_hook_events

    assert {"PreCompact", "Stop", "SessionStart"} <= registered_hook_events()
