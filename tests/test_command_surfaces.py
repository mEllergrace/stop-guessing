"""`exercise_commands` — the live-session half of `surface_validated`.

`plugin:`, `skill:` and `command:` surfaces could not be validated by any means. `runner.py:540` is
right that a proof run cannot drive them — a slash command needs a live session — but the fallback
was silence: `prompt.submit` recorded a prompt digest and never which command it was, so no evidence
existed to read either. Those five surfaces across CLAIM-17 and CLAIM-20 were unvalidatable by
construction, not by accident.

These tests build ledgers by hand so the evidence rules are pinned exactly, including the two that
matter most: an unverifiable ledger evidences nothing, and `skill:` is never claimed.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.attest.keys import _keyid
from stop_guessing.ledger.chain import ChainKey
from stop_guessing.ledger.sink import record
from stop_guessing.prove.procedures import exercise_commands
from stop_guessing.version import repo_root

#: The keyid must be the one `from_env` will DERIVE from this material, not a readable stand-in:
#: `_keyid` is `sg-<provider>-<digest>` and `same_key` compares on the digest, so a hand-written id
#: never matches the discovered key and the ledger silently fails to verify.
MATERIAL = b"k" * 32
KEY = ChainKey(_keyid(MATERIAL, "env"), MATERIAL)
PLUGIN = repo_root() / ".claude-plugin" / "plugins" / "stop-guessing"


def _ledger(tmp_path, *commands, key=KEY):
    path = tmp_path / "custody.jsonl"
    for command in commands:
        detail = {"prompt_digest": "sha256:x", "prompt_chars": 8}
        if command:
            detail["command"] = command
        record(path, {"op": "prompt.submit", "session_id": "s1",
                      "detail": json.dumps(detail, sort_keys=True)}, key)
    return path


def test_a_command_invoked_in_a_live_session_is_evidenced(tmp_path, monkeypatch):
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, {"name": "/custody", "path": str(PLUGIN / "commands" / "custody.md")})
    assert exercise_commands("command:/custody", ledger=led) == ["command:/custody"]


def test_a_command_never_invoked_is_not_evidenced(tmp_path, monkeypatch):
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, {"name": "/custody", "path": str(PLUGIN / "commands" / "custody.md")})
    assert exercise_commands("command:/no-noodle", ledger=led) == []


def test_the_plugin_is_reached_transitively_by_one_of_its_commands(tmp_path, monkeypatch):
    """A command whose defining file is under the plugin root could not have dispatched unless the
    plugin loaded. That is the whole of the claim, and it is deliberately narrow."""
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, {"name": "/custody", "path": str(PLUGIN / "commands" / "custody.md")})
    assert exercise_commands("plugin:stop-guessing", ledger=led) == ["plugin:stop-guessing"]


def test_a_command_from_somewhere_else_does_not_evidence_this_plugin(tmp_path, monkeypatch):
    """The control. Any command at all would otherwise validate the plugin surface."""
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, {"name": "/other", "path": "/somewhere/else/commands/other.md"})
    assert exercise_commands("plugin:stop-guessing", ledger=led) == []


def test_a_skill_is_never_claimed_from_a_command_record(tmp_path, monkeypatch):
    """A skill is loaded into context, not dispatched. Claiming it from a sibling command's record
    would be the overclaim this audit exists to prevent."""
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, {"name": "/custody", "path": str(PLUGIN / "commands" / "custody.md")})
    assert exercise_commands("skill:stop-guessing", ledger=led) == []


def test_an_unverifiable_ledger_evidences_nothing(tmp_path, monkeypatch):
    """The party whose surfaces this validates is the party that wrote the ledger.

    If the chain does not verify under its own key, counting its records would let that party
    validate its own claims by editing a file.
    """
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, {"name": "/custody", "path": str(PLUGIN / "commands" / "custody.md")})
    lines = led.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    target = tampered.get("predicate", tampered)
    target["session_id"] = "forged"          # content no longer matches its own hash
    led.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
    assert exercise_commands("command:/custody", ledger=led) == []


def test_a_prompt_with_no_command_evidences_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, None, None)
    assert exercise_commands("command:/custody", "plugin:stop-guessing", ledger=led) == []


def test_a_missing_ledger_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    assert exercise_commands("command:/custody", ledger=tmp_path / "nope.jsonl") == []


def test_only_the_kinds_it_can_speak_to_are_returned(tmp_path, monkeypatch):
    """`cli:` and `hook:` have their own exercisers; this must not double-count them."""
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, {"name": "/custody", "path": str(PLUGIN / "commands" / "custody.md")})
    got = exercise_commands("cli:\"stop-guessing doctor\"", "hook:PreToolUse", ledger=led)
    assert got == []


@pytest.mark.parametrize("surface", ["command:/custody", "plugin:stop-guessing"])
def test_the_end_to_end_shape_matches_what_the_hook_actually_writes(tmp_path, monkeypatch, surface):
    """Built from `command_boundary` itself, so this cannot pass on a shape the hook never emits."""
    from stop_guessing.cli.hook_lifecycle import command_boundary

    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", MATERIAL.decode())
    led = _ledger(tmp_path, command_boundary("/custody"))
    assert exercise_commands(surface, ledger=led) == [surface]
