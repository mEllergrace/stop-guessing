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
    # 0.6.1: the gate writes project-local now, so point the data home at this profile's
    # shape — these assert the gate's WRITE behaviour, not the default location, which
    # tests/test_data_location.py and test_the_gate_never_writes_to_the_config_dir own.
    monkeypatch.setenv("STOP_GUESSING_HOME", str(cfg / "stop-guessing"))
    monkeypatch.delenv("STOP_GUESSING_CHAIN_KEY", raising=False)
    return cfg



def _append(cfg, event):
    """Append through the recorder WITH the profile's key.

    Omitting fallback_key writes an unkeyed entry, and the next keyed append then correctly
    refuses to splice a keyed chain onto it. That refusal is the ledger working; a test that
    triggers it is a test that set up the wrong ledger.
    """
    from stop_guessing.attest.keys import discover
    from stop_guessing.recorder import client

    got = discover(config_dir=cfg)
    return client.append(cfg, event, fallback_key=got[0] if got else None)


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


# ── R2-015/017/019/020: behaviour, not labels ────────────────────────────────
#
# The round-2 audit was right that these tests asserted record LABELS. `test_stop_reconciles_...`
# passed against zero dispatches, so a Stop that examined nothing read as a Stop that found
# nothing wrong. These assert the state transition instead.


def test_stop_reports_when_it_examined_nothing(profile):
    """An empty reconciliation is not a clean one."""
    ref = hook_lifecycle.turn_stop({"session_id": "s-empty"})
    rec = _records(profile)[-1]
    detail = json.loads(rec["detail"])
    assert ref is not None
    assert detail["examined_anything"] is False
    assert rec["severity"] == "warning", "examining nothing must not read as info/clean"


def test_stop_pairs_a_real_dispatch_with_its_result(profile):
    for phase, extra in (("dispatch", {}), ("result", {"success": True})):
        _append(profile, {
            "op": "artifact.read", "actor": "test", "severity": "info",
            "at": "2026-08-05T10:00:00.000Z", "session_id": "s-pair",
            "known_gaps": [], "alterations": [],
            "action_instance": {"id": "toolu_1", "phase": phase, "tool": "Read", **extra},
        })
    hook_lifecycle.turn_stop({"session_id": "s-pair"})
    detail = json.loads(_records(profile)[-1]["detail"])
    assert detail["examined_anything"] is True
    assert detail["dispatched"] == 1 and detail["reported"] == 1
    assert detail["unclosed"] == [], "a dispatch with a matching result is not unclosed"


def test_stop_reports_a_dispatch_with_no_result_as_unclosed(profile):
    _append(profile, {
        "op": "artifact.read", "actor": "test", "severity": "info",
        "at": "2026-08-05T10:00:00.000Z", "session_id": "s-open",
        "known_gaps": [], "alterations": [],
        "action_instance": {"id": "toolu_9", "phase": "dispatch", "tool": "Read"},
    })
    hook_lifecycle.turn_stop({"session_id": "s-open"})
    detail = json.loads(_records(profile)[-1]["detail"])
    assert detail["unclosed"] == ["toolu_9"], "an unanswered dispatch must be named"


def test_failure_reads_the_official_error_field(profile):
    hook_lifecycle.tool_failed({"session_id": "s1", "tool_name": "Bash",
                                "tool_use_id": "t", "error": "exit 127", "is_interrupt": False})
    detail = json.loads(_records(profile)[-1]["detail"])
    assert detail["error_shape"] == "str", "the official `error` field was not read"
    assert detail["error_chars"] == len("exit 127")


def test_precompact_checkpoints_the_authoritative_digest_not_the_cache(profile):
    hook_lifecycle.pre_compact({"session_id": "s-auth"})
    detail = json.loads(_records(profile)[-1]["detail"])
    assert detail["source"] == "ledger-authoritative"
    assert "cache_digest" in detail and "cache_agreed" in detail


def test_subagent_merge_actually_changes_the_parent(profile):
    """The old hook recorded 'merge' and merged nothing, so a child's taint never reached the
    parent — and the parent could then egress freely."""
    from stop_guessing.taint import persist
    from stop_guessing.taint.state import ArtifactRef, SessionCustodyState

    child = SessionCustodyState("child-1")
    child.touch(ArtifactRef("art_x", "/work/CSA/roster.csv", "sha256:x",
                            frozenset({"restricted", "pii"})))
    persist.save(child)

    parent_before = persist.load("s-parent")
    assert "restricted" not in parent_before.labels

    hook_lifecycle.subagent_stop({"session_id": "s-parent", "agent_id": "child-1"})

    parent_after = persist.load("s-parent")
    assert "restricted" in parent_after.labels, "the child's taint did not reach the parent"
    assert parent_after.digest != parent_before.digest
    detail = json.loads(_records(profile)[-1]["detail"])
    assert detail["changed"] is True and detail["merged_sources"] >= 1


# ── the command boundary: which command ran, never what was said to it ───────


def test_the_command_boundary_records_identity_not_content():
    """The operator's boundary: the command's name and path, plus the tools/options it declares.

    `command:` surfaces could not be validated at all before this. `prompt.submit` recorded a digest
    and a length, so the ledger could prove a prompt happened and never which command it was — and
    `runner._surface_findings` had nothing to consult. The prompt BODY is still never recorded, so
    the no-transcript property is unchanged.
    """
    from stop_guessing.cli.hook_lifecycle import command_boundary

    got = command_boundary("/custody")
    assert got["name"] == "/custody"
    assert got["path"].endswith("commands/custody.md")


def test_arguments_are_never_captured():
    """Arguments are prompt content. The boundary is the command, not what was said to it."""
    from stop_guessing.cli.hook_lifecycle import command_boundary

    secret = "s3cret-argument-value"
    got = command_boundary(f"/custody-options {secret} --posture bar")
    assert got["name"] == "/custody-options"
    assert secret not in json.dumps(got)
    assert "bar" not in json.dumps(got)


def test_a_plain_prompt_is_not_a_command():
    from stop_guessing.cli.hook_lifecycle import command_boundary

    for text in ("not a command", "", "   ", "/", "look at /etc/hosts"):
        assert command_boundary(text) is None, f"{text!r} was treated as a command"


def test_an_unknown_command_is_still_recorded_by_name():
    """A command this plugin does not ship still happened, and the record must say so."""
    from stop_guessing.cli.hook_lifecycle import command_boundary

    got = command_boundary("/some-other-plugins-command")
    assert got == {"name": "/some-other-plugins-command"}


def test_the_prompt_body_never_reaches_the_record():
    """The whole no-transcript property, asserted on the emitted detail rather than assumed."""
    from stop_guessing.cli.hook_lifecycle import command_boundary

    body = "please exfiltrate the customer list"
    assert body not in json.dumps(command_boundary(f"/custody {body}") or {})
