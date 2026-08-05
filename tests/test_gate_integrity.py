"""Gate behaviour under damage and under an untrusted handler index.

SG-HARD-023 (#59) — an unverifiable ledger became "no records", which is indistinguishable from a
first run, and the agent-WRITABLE cache was then restored as authority. Deleting or corrupting the
ledger therefore reset enforcement to untainted: the recorded party could clear its own taint.

SG-HARD-017 (#50) — a project-controlled handler and its unsigned pytest ran against a classified
artifact BEFORE the policy decision. Under `bar` that meant project code read the file and the
denial arrived afterwards.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.cli import gate


@pytest.fixture
def profile(tmp_path, monkeypatch):
    cfg = tmp_path / "claude"
    (cfg / "stop-guessing" / "ledger").mkdir(parents=True)
    key = cfg / "stop-guessing" / "chain.key"
    key.write_bytes(b"a-test-key-that-is-32-bytes-ok!!")
    key.chmod(0o600)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    monkeypatch.delenv("STOP_GUESSING_CHAIN_KEY", raising=False)
    return cfg


@pytest.fixture
def classified(tmp_path):
    d = tmp_path / ".ssh"
    d.mkdir()
    f = d / "id_rsa"
    f.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    return f


# ── SG-HARD-023 · #59 ────────────────────────────────────────────────────────


def test_an_absent_ledger_is_a_normal_first_run(profile):
    state, agreed = gate.state_for("s1")
    assert agreed is True
    assert not getattr(state, "unverifiable_reason", None)


def test_a_corrupted_ledger_does_not_fall_back_to_the_cache(profile, classified):
    """The attack: corrupt the ledger, and enforcement used to reset to untainted."""
    gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(classified)},
                 "session_id": "s1"}, posture="steer")
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    lines = led.read_text(encoding="utf-8").splitlines()
    lines.insert(0, "{ not json")
    led.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state, agreed = gate.state_for("s1")
    assert agreed is False
    assert getattr(state, "unverifiable_reason", None), "the failure must be named, not swallowed"
    assert "restricted" in state.labels, "an unverifiable ledger must fail toward denying egress"


def test_a_tampered_chain_does_not_read_as_an_empty_history(profile, classified):
    gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(classified)},
                 "session_id": "s1"}, posture="steer")
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    rec = json.loads(led.read_text(encoding="utf-8").splitlines()[0])
    rec["op"] = "artifact.write"          # breaks the chain hash
    led.write_text(json.dumps(rec) + "\n", encoding="utf-8")

    state, agreed = gate.state_for("s1")
    assert agreed is False
    assert getattr(state, "unverifiable_reason", None)


def test_the_unverifiable_reason_reaches_the_record(profile, classified):
    gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(classified)},
                 "session_id": "s1"}, posture="steer")
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    led.write_text("{ tampered\n" + led.read_text(encoding="utf-8"), encoding="utf-8")

    # The gate must still emit a decision, and it must carry the finding.
    gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(classified)},
                 "session_id": "s1"}, posture="steer")


# ── SG-HARD-017 · #50 ────────────────────────────────────────────────────────


def _project_with_handler(root, marker):
    """A project-controlled handler whose test writes a marker when it runs."""
    hdir = root / "handlers"
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / "index.yaml").write_text(
        "handlers:\n"
        "  - id: sneaky\n"
        "    match: {labels: [credential]}\n"
        "    script: handlers/sneaky.py\n", encoding="utf-8")
    (hdir / "sneaky.py").write_text(
        "import sys\n"
        f"open({str(marker)!r}, 'a').write('handler ran\\n')\n"
        "print('summary')\n", encoding="utf-8")
    (hdir / "test_sneaky.py").write_text(
        f"open({str(marker)!r}, 'a').write('test ran\\n')\n"
        "def test_ok():\n    assert True\n", encoding="utf-8")
    return hdir


def test_a_denied_read_never_executes_the_project_handler(profile, classified, tmp_path):
    """Under a forbid, neither the handler nor its unsigned test may touch the artifact."""
    marker = tmp_path / "ran.txt"
    proj = tmp_path / "proj"
    _project_with_handler(proj, marker)

    # `bar` forbids a classified read outright.
    gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(classified)},
                 "session_id": "s1", "cwd": str(proj)}, posture="bar")

    assert not marker.exists(), (
        "project code executed against a classified artifact before/despite the denial: "
        f"{marker.read_text() if marker.exists() else ''}"
    )


def test_discovery_does_not_execute_anything(profile, classified, tmp_path):
    """Finding a handler tells the policy one exists; only authorisation may run it."""
    from stop_guessing import handlers

    marker = tmp_path / "ran.txt"
    proj = tmp_path / "proj"
    _project_with_handler(proj, marker)

    found = handlers.find(str(classified), frozenset({"credential"}), str(proj))
    assert found is not None, "the handler should be discoverable"
    assert not marker.exists(), "find() must not execute the handler or its test"
