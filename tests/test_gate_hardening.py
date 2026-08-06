"""The P0 gate fixes from the 2026-08-04 hardening audit.

Each test is the mutation the audit named. The point is not that the code has a new branch — it is
that performing the attack now changes the verdict, where before it did not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stop_guessing.ledger.chain import ChainKey
from stop_guessing.ledger.sink import load, record
from stop_guessing.prove import runner

KEY = ChainKey("test-key", b"a-test-key-that-is-32-bytes-ok!!")


@pytest.fixture
def ledger(tmp_path) -> Path:
    p = tmp_path / "proofs.jsonl"
    for i in range(3):
        record(p, {"op": "proof.run", "claim": f"CLAIM-{i:02d}", "passed": True,
                   "actor": "test", "severity": "info",
                   "at": f"2026-08-04T10:00:{i:02d}.000Z"}, KEY)
    return p


# ── SG-HARD-004 · #37 — a truncated ledger must not attest ───────────────────


def test_a_torn_final_record_makes_the_chain_unusable(ledger):
    """The prefix still verifies. That is exactly why it must not pass."""
    before = load(ledger, KEY)
    assert before.chain.intact and not before.truncated

    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"op": "proof.run", "claim": "CLAIM-99", "pas')  # torn write

    after = load(ledger, KEY)
    assert after.chain.intact, "the intact prefix is the whole danger; it still verifies"
    assert after.truncated, "and load() knows it is a prefix"


def test_check_treats_a_truncated_ledger_as_not_intact(ledger, monkeypatch):
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"op": "proof.run", "clai')

    result = runner.check(KEY, ledger)
    assert result["chain_truncated"] is True
    assert result["chain_verified"] is True, "the hash chain over the prefix is fine"
    assert result["chain_intact"] is False, "but the usable verdict must be false"
    assert result["ok"] is False
    assert not any(r["proven"] for r in result["rows"]), \
        "no claim may be proven by a ledger that is only a prefix"


def test_the_truncation_reason_does_not_masquerade_as_a_hash_break(ledger):
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write("{oh dear")
    result = runner.check(KEY, ledger)
    assert "partial" in (result["chain_reason"] or "").lower()


# ── SG-HARD-002 · #35 — a missing procedure must invalidate ──────────────────


def test_a_claim_with_no_current_procedure_is_not_proven(ledger, monkeypatch):
    """Delete the procedure, keep the passing record: the claim must stop being proven."""
    claims = {"meta": {"version": "test"},
              "claims": [{"id": "CLAIM-01", "proof_kind": "live-run", "proofs": [],
                          "statement": "x", "surface": []}]}
    monkeypatch.setattr(runner, "load_claims", lambda: claims)
    monkeypatch.setattr(runner, "all_procedures", dict)  # registry is empty

    result = runner.check(KEY, ledger)
    row = result["rows"][0]
    assert row["has_procedure"] is False
    assert row["proven"] is False, "a claim nobody can re-run is not proven"


def test_kind_matches_is_false_when_the_procedure_is_gone(ledger, monkeypatch):
    """It used to report kind_matches=True for an absent procedure, which read as fine."""
    claims = {"meta": {}, "claims": [{"id": "CLAIM-01", "proof_kind": "live-run",
                                      "proofs": [], "statement": "x", "surface": []}]}
    monkeypatch.setattr(runner, "load_claims", lambda: claims)
    monkeypatch.setattr(runner, "all_procedures", dict)
    assert runner.check(KEY, ledger)["rows"][0]["kind_matches"] is False


# ── SG-HARD-001 · #34 — declared surfaces must exist ─────────────────────────


def test_a_claim_naming_an_unregistered_hook_is_not_proven(ledger, monkeypatch):
    claims = {"meta": {}, "claims": [{"id": "CLAIM-01", "proof_kind": "live-run", "proofs": [],
                                      "statement": "x", "surface": ["hook:PreCompact"]}]}
    monkeypatch.setattr(runner, "load_claims", lambda: claims)
    monkeypatch.setattr(runner, "all_procedures", dict)
    monkeypatch.setattr(runner, "registered_hook_events", lambda root=None: {"PreToolUse"})

    row = runner.check(KEY, ledger)["rows"][0]
    assert row["surface_findings"], "an unregistered hook must be a finding"
    assert "PreCompact" in row["surface_findings"][0]
    assert row["proven"] is False


def test_a_registered_hook_still_fails_unless_the_proof_exercised_it(monkeypatch):
    """R2-003. Registration is not execution, and this test used to assert the opposite.

    It passed a registered hook and expected no finding — which is exactly the gap round two
    named: a claim declaring `hook:PreCompact` cleared because the event appeared in hooks.json,
    while its procedure called rebuild() in memory and never went near the hook.
    """
    monkeypatch.setattr(runner, "registered_hook_events", lambda root=None: {"PreToolUse"})

    findings, unvalidated = runner._surface_findings(
        {"id": "CLAIM-01", "surface": ["hook:PreToolUse"]}, exercised=set())
    assert findings, "a registered but unexercised hook must be a finding"
    assert "did not exercise" in findings[0]

    findings, unvalidated = runner._surface_findings(
        {"id": "CLAIM-01", "surface": ["hook:PreToolUse"]}, exercised={"hook:PreToolUse"})
    assert findings == [], "a hook the proof actually drove must pass"
    assert unvalidated == []


def test_cli_surfaces_must_be_executed_and_host_surfaces_read_as_unchecked(monkeypatch):
    """R2-003/R2-039. `cli:` moved from unvalidated to executed; host-loaded surfaces did not.

    This test previously asserted that a `cli:` surface was merely *reported* unvalidated and did
    not block — which is the defect: 21 declared commands were never run, and four of them did not
    exist. A CLI surface is executable from a proof run, so it must be executed. A plugin, skill or
    slash command is loaded by the HOST and cannot be, so it stays unchecked rather than passed.
    """
    monkeypatch.setattr(runner, "registered_hook_events", lambda root=None: {"PreToolUse"})

    # `skill:stop-guessing` — the one that actually ships. The placeholder this test used
    # (`skill:custody`) names a skill the plugin does not contain, and now correctly produces a
    # structural finding; using it here made "an executed cli surface passes" fail for a reason
    # that had nothing to do with the cli surface.
    REAL = "skill:stop-guessing"

    findings, unvalidated = runner._surface_findings(
        {"id": "CLAIM-01", "surface": ['cli:"stop-guessing attest"', REAL]},
        exercised=set())
    assert findings, "an unexecuted cli surface must block"
    assert any("did not execute" in f for f in findings)
    assert unvalidated == [REAL], "host-loaded surfaces stay unchecked, not passed"

    findings, unvalidated = runner._surface_findings(
        {"id": "CLAIM-01", "surface": ['cli:"stop-guessing attest"', REAL]},
        exercised={'cli:"stop-guessing attest"'})
    assert findings == [], f"an executed cli surface passes, got {findings}"
    assert unvalidated == [REAL]

    # And the strengthening: a host-loaded surface that does NOT ship is no longer merely
    # "unchecked". It cannot be executed here, but whether it exists at all is decidable, and a
    # declared skill the plugin does not contain is a defect rather than an open question.
    findings, unvalidated = runner._surface_findings(
        {"id": "CLAIM-01", "surface": ["skill:does-not-exist"]},
        exercised=set())
    assert findings, "a declared skill that does not ship was reported as merely unchecked"
    assert unvalidated == ["skill:does-not-exist"], (
        "it must STILL read as unexecuted — structural soundness is not execution")


def test_every_hook_a_claim_declares_is_actually_registered():
    """This test previously asserted the DEFECT, and failed the moment it was fixed.

    That was deliberate — it was written to fail loudly rather than silently pass once
    `PreCompact`, `Stop` and `SessionStart` were registered, so the audit record could not drift
    out of date behind a green suite. They are now registered (#42/#81), so it asserts the property
    instead: no claim may declare a surface the shipped plugin does not provide.
    """
    registered = runner.registered_hook_events()
    declared = {
        str(s).split(":", 1)[1]
        for c in runner.load_claims()["claims"]
        for s in (c.get("surface") or [])
        if str(s).startswith("hook:")
    }
    missing = declared - registered
    assert not missing, (
        f"claims declare hook(s) the plugin does not register: {sorted(missing)}. "
        f"Registered: {sorted(registered)}"
    )
    assert {"PreCompact", "SessionStart", "Stop"} <= registered


# ── SG-HARD-047 · #80 — exports must refuse a prefix ─────────────────────────


def test_export_refuses_a_truncated_ledger(ledger, capsys):
    from stop_guessing.cli import cmd_ops

    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"op": "artifact.rea')

    class Args:
        path = str(ledger)
        format = "prov"
        keyfile = None
        out = None

    monkey = Args()
    import stop_guessing.cli.cmd_ops as m

    orig = m._key
    m._key = lambda a: KEY
    try:
        rc = cmd_ops.cmd_export(monkey)
    finally:
        m._key = orig
    assert rc == 1
    assert "prefix" in capsys.readouterr().out.lower()


# ── SG-HARD-005 · #38 — the exit code is a contract ──────────────────────────


def test_claims_check_returns_2_when_it_cannot_verify(ledger, capsys, monkeypatch):
    """No key means nothing was checked, which must not look like success."""
    from stop_guessing.cli import cmd_prove

    class Args:
        keyfile = None
        ledger = str(ledger)

    monkeypatch.setattr(cmd_prove, "_key", lambda a: None)
    monkeypatch.setattr(runner, "load_claims",
                        lambda: {"meta": {}, "claims": [
                            {"id": "CLAIM-01", "proof_kind": "live-run", "proofs": [],
                             "statement": "x", "surface": []}]})
    rc = cmd_prove.cmd_claims_check(Args())
    assert rc == 2
    assert "CANNOT VERIFY" in capsys.readouterr().out


def test_the_ci_workflow_propagates_a_failing_claims_gate():
    ci = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
    body = ci.read_text(encoding="utf-8")
    assert "exit 1" in body, "a finding must fail the job"
    assert 'exit "$rc"' in body, "a crashed command must fail the job"
    assert "CANNOT VERIFY" in body, "cannot-verify must be distinguished, not silently passed"


def test_hooks_json_is_parseable_and_its_events_are_discoverable():
    events = runner.registered_hook_events()
    assert events, "the plugin must register at least one event"
    assert events <= {"PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart",
                      "SessionEnd", "Stop", "SubagentStop", "PreCompact", "UserPromptSubmit",
                      "PermissionRequest", "PostToolBatch", "ConfigChange"}, \
        f"unexpected event name in hooks.json: {events}"
    json.dumps(sorted(events))  # serialisable, for the record


# ── the offline audit must tell local IPC from egress ────────────────────────


def test_af_unix_is_not_treated_as_a_network_call(tmp_path):
    """A unix socket has no address family that could leave the host.

    The scanner matched the generic `socket.socket(` shape and flagged the recorder's own client
    and daemon — the one component designed never to touch the network — which made CLAIM-18
    unprovable for the wrong reason.
    """
    from stop_guessing.recorder.network import audit

    (tmp_path / "ipc.py").write_text(
        "import socket\ns = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n", encoding="utf-8")
    result = audit(tmp_path)
    assert result["unexpected"] == []
    assert result["sites"][0]["allowed"] is True


def test_af_inet_is_still_caught(tmp_path):
    """The control case. Recognising AF_UNIX must not blind the audit to a real socket."""
    from stop_guessing.recorder.network import audit

    (tmp_path / "egress.py").write_text(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n", encoding="utf-8")
    result = audit(tmp_path)
    assert len(result["unexpected"]) == 1
    assert "AF_INET" in result["unexpected"][0]["text"]


def test_the_exemption_is_by_address_family_not_by_file(tmp_path):
    """A path-based exemption would also excuse a real socket added to that file later."""
    from stop_guessing.recorder.network import audit

    (tmp_path / "mixed.py").write_text(
        "import socket\n"
        "a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n", encoding="utf-8")
    result = audit(tmp_path)
    assert len(result["unexpected"]) == 1, "the AF_INET line in the same file must still be caught"
    assert "AF_INET" in result["unexpected"][0]["text"]
