"""Data belongs beside the work, not in the agent's config directory.

Found by the operator: every path for evidence resolved under `$CLAUDE_CONFIG_DIR`
(`~/.claude-ies/stop-guessing/`). That directory belongs to the agent and is shared by every session
and project running on that profile.

Measured before changing anything: **31 state files, ~24 of them real Claude Code session UUIDs**,
pooled from whatever projects happened to be open. And each record carried `session_id` with no `cwd`
— so not one of them could be attributed to a project even in principle. A provenance tool had
produced two dozen unattributable records, in someone else's directory.

Both halves are tested here: where data goes, and whether it can be traced back.
"""

from __future__ import annotations

import json
from pathlib import Path

from stop_guessing import paths


def test_the_default_is_the_directory_it_is_called_from(tmp_path, monkeypatch):
    monkeypatch.delenv("STOP_GUESSING_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    assert paths.data_home() == tmp_path / ".stop-guessing"
    assert paths.ledger_file() == tmp_path / ".stop-guessing" / "ledger" / "custody.jsonl"
    assert paths.state_dir() == tmp_path / ".stop-guessing" / "state"


def test_nothing_resolves_into_the_agent_config_dir(tmp_path, monkeypatch):
    """The regression itself. A profile path here means data lands in a shared directory again."""
    monkeypatch.delenv("STOP_GUESSING_HOME", raising=False)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.chdir(tmp_path)
    for resolved in (paths.data_home(), paths.ledger_file(), paths.state_dir(), paths.locks_dir()):
        assert "claude" not in resolved.parts, f"{resolved} still resolves under the agent's dir"


def test_the_override_keeps_a_shared_store_available(tmp_path, monkeypatch):
    """Never close an option: a single-project machine or a central collector may want one store."""
    shared = tmp_path / "central"
    monkeypatch.setenv("STOP_GUESSING_HOME", str(shared))
    monkeypatch.chdir(tmp_path)
    assert paths.data_home() == shared
    assert paths.ledger_file() == shared / "ledger" / "custody.jsonl"


def test_writes_never_silently_fall_back_to_the_legacy_location(tmp_path, monkeypatch):
    """A tool that keeps writing where data already is never actually migrates."""
    monkeypatch.delenv("STOP_GUESSING_HOME", raising=False)
    legacy = tmp_path / "claude" / "stop-guessing" / "ledger"
    legacy.mkdir(parents=True)
    (legacy / "custody.jsonl").write_text('{"seq":0}\n', encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.chdir(tmp_path)
    assert paths.ledger_file() == tmp_path / ".stop-guessing" / "ledger" / "custody.jsonl"


def test_the_legacy_location_is_still_found_and_reported(tmp_path, monkeypatch):
    """Accumulated evidence is not disposable state, so it must not become invisible."""
    legacy = tmp_path / "claude" / "stop-guessing"
    (legacy / "ledger").mkdir(parents=True)
    (legacy / "ledger" / "custody.jsonl").write_text('{"seq":0}\n{"seq":1}\n', encoding="utf-8")
    (legacy / "state").mkdir()
    (legacy / "state" / "a.json").write_text("{}", encoding="utf-8")

    found = paths.legacy_data_found(legacy.parent)
    assert found["exists"] and found["ledger"]
    assert found["ledger_records"] == 2
    assert found["state_files"] == 1
    assert "not moved automatically" in found["note"].lower()


def test_state_records_the_project_it_belongs_to(tmp_path, monkeypatch):
    """The other half of the defect: 31 pooled files, none attributable.

    A provenance record that cannot say where it came from is doing half its job.
    """
    from stop_guessing.taint import persist
    from stop_guessing.taint.state import SessionCustodyState

    monkeypatch.delenv("STOP_GUESSING_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    written = persist.save(SessionCustodyState("attrib-test"))
    assert tmp_path in written.parents, f"state landed outside the project: {written}"
    body = json.loads(written.read_text(encoding="utf-8"))
    assert body["project"] == str(tmp_path), "the state file does not record its project"
    assert body["session_id"] == "attrib-test"


def test_the_legacy_state_accessor_is_kept():
    """Never remove an existing function — something outside this repo may read the old path."""
    from stop_guessing.taint import persist

    assert callable(persist.legacy_state_dir)
    assert "stop-guessing" in str(persist.legacy_state_dir())


def test_config_is_deliberately_not_moved():
    """`stop-guessing.json` is a SETTING, and a profile-level config layer is intended.

    The objection was to data, not settings. Moving the posture config would break the documented
    four-layer chain, so it is left where it is on purpose.
    """
    src = (Path(__file__).resolve().parent.parent
           / "stop_guessing" / "cli" / "hook_gate.py").read_text(encoding="utf-8")
    assert 'Path(cfg) / "stop-guessing.json"' in src, (
        "the profile config layer was removed; posture resolution now has a hole in it")
