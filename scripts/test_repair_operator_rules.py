"""Tests for the operator-rule repair (#87). Written and passing BEFORE it touches a live profile."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from repair_operator_rules import main, missing_rules, repair  # noqa: E402


def _profile(tmp_path, entries, with_hook=True):
    prof = tmp_path / "claude"
    (prof / "hooks").mkdir(parents=True)
    if with_hook:
        (prof / "hooks" / "check_credentials.sh").write_text("#!/bin/bash\nexit 0\n")
    (prof / "settings.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": [{"hooks": [{"command": c} for c in entries]}]}}), encoding="utf-8")
    return prof / "settings.json"


def _commands(settings):
    d = json.loads(settings.read_text())
    return [h["command"] for g in d["hooks"]["PreToolUse"] for h in g["hooks"]]


def test_a_removed_registration_is_detected(tmp_path):
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"])
    assert missing_rules(s) == ["check_credentials.sh"]


def test_an_intact_registration_is_not_reported(tmp_path):
    """The control: a repair that always finds damage would rewrite settings.json forever."""
    s = _profile(tmp_path, ["bash /x/hooks/check_credentials.sh", "bash /x/hooks/coc_gate.sh"])
    assert missing_rules(s) == []


def test_it_does_not_register_a_hook_that_is_not_installed(tmp_path):
    """Registering a missing file would error on every tool call. That is not a repair."""
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"], with_hook=False)
    assert missing_rules(s) == []


def test_repair_restores_it_first_in_the_order(tmp_path):
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"])
    assert repair(s) == ["check_credentials.sh"]
    cmds = _commands(s)
    assert "check_credentials.sh" in cmds[0], "the credential check must run before anything else"
    assert any("coc_gate.sh" in c for c in cmds), "the repair removed our own gate"


def test_repair_uses_a_resolved_absolute_path(tmp_path):
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"])
    repair(s)
    cmd = _commands(s)[0]
    assert "~" not in cmd, "a literal ~ expands at hook-execution time under whatever HOME is set"
    assert cmd.startswith("bash /")


def test_repair_is_idempotent(tmp_path):
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"])
    repair(s)
    first = s.read_text()
    assert repair(s) == []
    assert s.read_text() == first, "a second repair modified the file"


def test_repair_writes_a_backup(tmp_path):
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"])
    repair(s)
    assert list(s.parent.glob("settings.json.bak-*")), "no backup was written"


def test_repair_preserves_unrelated_settings(tmp_path):
    prof = tmp_path / "claude"
    (prof / "hooks").mkdir(parents=True)
    (prof / "hooks" / "check_credentials.sh").write_text("#!/bin/bash\nexit 0\n")
    s = prof / "settings.json"
    s.write_text(json.dumps({
        "model": "opus", "statusLine": {"type": "command"},
        "hooks": {"PreToolUse": [{"hooks": [{"command": "bash /x/coc_gate.sh"}]}],
                  "Stop": [{"hooks": [{"command": "bash /x/other.sh"}]}]}}), encoding="utf-8")
    repair(s)
    d = json.loads(s.read_text())
    assert d["model"] == "opus"
    assert d["statusLine"] == {"type": "command"}
    assert d["hooks"]["Stop"][0]["hooks"][0]["command"] == "bash /x/other.sh"


def test_dry_run_changes_nothing(tmp_path):
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"])
    before = s.read_text()
    assert repair(s, dry_run=True) == ["check_credentials.sh"]
    assert s.read_text() == before


def test_check_exits_nonzero_on_damage(tmp_path, capsys):
    s = _profile(tmp_path, ["bash /x/hooks/coc_gate.sh"])
    assert main(["--profile", str(s.parent), "--check"]) == 1
    assert "MISSING" in capsys.readouterr().out


def test_check_exits_zero_when_intact(tmp_path):
    s = _profile(tmp_path, ["bash /x/hooks/check_credentials.sh"])
    assert main(["--profile", str(s.parent), "--check"]) == 0
