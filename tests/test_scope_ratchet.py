"""The scope ratchet, tested against the thing it was built for: me.

While closing an audit finding I withdrew six `hook:` surfaces and five `plugin:`/`skill:`/
`command:` surfaces from the claims because their proofs did not exercise them — and that is what
flipped `surface_validated` to true. The claim-definition digest noticed the claims had *changed*.
Nothing noticed they had got *smaller*, and nothing connected that to the verdict improving.

That is a chain-of-custody failure before it is a metrics failure. ISO/IEC 27037 §5.4.1 requires
any alteration to evidence to carry a written justification, and this record schema already makes
`alterations` a Tier-A required field for exactly that reason. Reducing what a claim asserts
alters the evidence subject. I made that alteration by editing YAML and recorded nothing.

These tests assert the control, in both directions: an unrecorded reduction is a finding, and a
recorded one with a reason is not. Narrowing stays legal — narrowing *silently* does not.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.prove import scope


def _scope_record(claim_id, surfaces, aicm=()):
    ev = scope.scope_event({"id": claim_id, "surface": list(surfaces), "aicm": list(aicm)})
    ev.update({"actor": "test", "at": "2026-08-05T10:00:00.000Z", "severity": "info"})
    return ev


def _retraction(claim_id, field, removed, reason):
    ev = scope.retraction_event(claim_id, field, removed, reason)
    ev.update({"actor": "test", "at": "2026-08-05T11:00:00.000Z"})
    return ev


# ── the defect itself ────────────────────────────────────────────────────────


def test_a_silently_removed_surface_is_a_finding():
    """The exact edit I made: drop `hook:PreCompact`, say nothing, watch the metric improve."""
    entries = [_scope_record("CLAIM-11", ["cli:x", "hook:PreCompact"])]
    now = {"id": "CLAIM-11", "surface": ["cli:x"], "aicm": []}

    found = scope.retractions(entries, now)
    assert found, "removing a declared surface produced no finding"
    assert not found[0].justified
    assert "hook:PreCompact" in found[0].removed
    assert "NO RECORDED RETRACTION" in found[0].describe()


def test_a_removed_control_mapping_is_also_a_finding():
    """Dropping an AICM control quietly reduces what the questionnaire can cite."""
    entries = [_scope_record("CLAIM-02", ["cli:x"], aicm=["LOG-03", "LOG-10"])]
    now = {"id": "CLAIM-02", "surface": ["cli:x"], "aicm": ["LOG-03"]}
    found = scope.retractions(entries, now)
    assert any("LOG-10" in r.removed for r in found)


def test_a_recorded_retraction_with_a_reason_is_not_a_finding():
    """Narrowing is legitimate. Narrowing silently is what this forbids."""
    entries = [
        _scope_record("CLAIM-11", ["cli:x", "hook:PreCompact"]),
        _retraction("CLAIM-11", "surface", ["hook:PreCompact"],
                    "the proof exercises rebuild() directly and does not drive the hook"),
    ]
    now = {"id": "CLAIM-11", "surface": ["cli:x"], "aicm": []}
    found = scope.retractions(entries, now)
    assert found and all(r.justified for r in found)
    assert "does not drive the hook" in found[0].describe()


def test_a_retraction_with_no_reason_is_refused_at_the_source():
    with pytest.raises(ValueError, match="without a reason"):
        scope.retraction_event("CLAIM-01", "surface", ["hook:PostToolUse"], "   ")


def test_an_empty_reason_does_not_justify_anything():
    """Belt and braces: even if such a record existed, it must not excuse the removal."""
    bad = {"op": scope.RETRACTION_OP, "claim": "CLAIM-01",
           "detail": json.dumps({"field": "surface", "removed": ["hook:PostToolUse"],
                                 "reason": ""})}
    entries = [_scope_record("CLAIM-01", ["hook:PostToolUse"]), bad]
    now = {"id": "CLAIM-01", "surface": [], "aicm": []}
    found = scope.retractions(entries, now)
    assert found and not found[0].justified


# ── the ways a reduction could hide ──────────────────────────────────────────


def test_shrinking_one_surface_at_a_time_still_registers():
    """High-water, not last-value. Nobody removes ten things at once."""
    entries = [
        _scope_record("CLAIM-20", ["plugin:p", "skill:s", "command:/c"]),
        _scope_record("CLAIM-20", ["plugin:p", "skill:s"]),      # one goes
        _scope_record("CLAIM-20", ["plugin:p"]),                 # another goes
    ]
    now = {"id": "CLAIM-20", "surface": ["plugin:p"], "aicm": []}
    removed = {x for r in scope.retractions(entries, now) for x in r.removed}
    assert removed == {"skill:s", "command:/c"}, (
        "a claim shrunk gradually must still measure against the largest scope ever asserted"
    )


def test_growing_scope_is_never_a_finding():
    """The ratchet turns one way. Claiming MORE needs proof, not permission."""
    entries = [_scope_record("CLAIM-01", ["cli:x"])]
    now = {"id": "CLAIM-01", "surface": ["cli:x", "hook:PostToolUse"], "aicm": []}
    assert scope.retractions(entries, now) == []


def test_a_claim_with_no_history_has_no_retractions():
    assert scope.retractions([], {"id": "CLAIM-99", "surface": ["cli:x"], "aicm": []}) == []


def test_readding_a_surface_clears_the_finding():
    """Putting it back is the other honest remedy, and it must be recognised as one."""
    entries = [_scope_record("CLAIM-01", ["hook:PostToolUse"])]
    now = {"id": "CLAIM-01", "surface": ["hook:PostToolUse"], "aicm": []}
    assert scope.retractions(entries, now) == []


# ── it is an ISO 27037 alteration, not a bespoke concept ────────────────────


def test_a_retraction_records_an_alteration_with_its_justification():
    ev = scope.retraction_event("CLAIM-10", "surface", ["hook:PreToolUse"],
                                "the proof calls the policy engine directly")
    alt = ev["alterations"]
    assert alt, "a scope reduction must appear in `alterations`, the Tier-A field for exactly this"
    assert alt[0]["kind"] == "scope-retraction"
    assert alt[0]["justification"] == "the proof calls the policy engine directly"
    assert alt[0]["what"] == "claim.CLAIM-10.surface"


def test_a_retraction_states_the_reduction_as_a_known_gap():
    ev = scope.retraction_event("CLAIM-13", "surface", ["hook:Stop"], "reason enough")
    assert any("asserts less than it did" in g for g in ev["known_gaps"])


def test_the_scope_record_pins_what_was_asserted():
    ev = scope.scope_event({"id": "CLAIM-07", "surface": ["hook:PreToolUse", "cli:x"],
                            "aicm": ["DSP-20"]})
    detail = json.loads(ev["detail"])
    assert detail["scope"]["surface"] == ["cli:x", "hook:PreToolUse"]   # canonical order
    assert detail["scope"]["aicm"] == ["DSP-20"]
    assert detail["digest"], "the scope must be digestible so a change is detectable"


def test_the_scope_digest_changes_when_scope_shrinks():
    big = {"id": "C", "surface": ["a", "b"], "aicm": []}
    small = {"id": "C", "surface": ["a"], "aicm": []}
    assert scope.scope_digest(big) != scope.scope_digest(small)


def test_a_scope_record_declares_its_own_limitation():
    """`known_gaps: []` is a positive assertion. Writing it while knowing about a gap is the same
    overclaim this whole module exists to catch, one level up."""
    ev = scope.scope_event({"id": "C", "surface": ["a"], "aicm": []})
    assert ev["known_gaps"], "the scope record asserts no gaps while the ratchet has a known one"
    text = " ".join(ev["known_gaps"]).lower()
    assert "statement text" in text, "the statement-text limitation is not declared"
    assert "surface" in text and "aicm" in text, "the record does not say what IS covered"


# ── the CLI that makes a retraction a deliberate act ─────────────────────────


def test_the_retract_command_records_a_reasoned_reduction(tmp_path):
    """End to end through the CLI, against a temp ledger — the surface an operator actually uses."""
    import subprocess
    import sys

    from stop_guessing.version import repo_root

    ledger = tmp_path / "l.jsonl"
    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.main", "retract",
         "--claim", "CLAIM-11", "--field", "surface", "--removed", "hook:PreCompact",
         "--reason", "the proof exercises rebuild() directly and does not drive the hook",
         "--ledger", str(ledger)],
        capture_output=True, text=True, cwd=str(repo_root()), timeout=300,
        stdin=subprocess.DEVNULL)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "no longer asserts" in res.stdout
    assert "ISO 27037 alteration" in res.stdout

    entries = [json.loads(ln) for ln in ledger.read_text(encoding="utf-8").splitlines() if ln.strip()]
    rec = [e for e in entries if e.get("op") == scope.RETRACTION_OP]
    assert rec, "the retraction was not written to the ledger"
    assert rec[0]["alterations"][0]["kind"] == "scope-retraction"

    # And it must actually excuse the removal it names.
    hist = [_scope_record("CLAIM-11", ["cli:x", "hook:PreCompact"]), *entries]
    found = scope.retractions(hist, {"id": "CLAIM-11", "surface": ["cli:x"], "aicm": []})
    assert found and all(r.justified for r in found)


def test_the_retract_command_refuses_an_empty_reason(tmp_path):
    import subprocess
    import sys

    from stop_guessing.version import repo_root

    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.main", "retract",
         "--claim", "CLAIM-11", "--field", "surface", "--removed", "hook:PreCompact",
         "--reason", "   ", "--ledger", str(tmp_path / "l.jsonl")],
        capture_output=True, text=True, cwd=str(repo_root()), timeout=300,
        stdin=subprocess.DEVNULL)
    assert res.returncode == 2, res.stdout
    assert "REFUSED" in res.stdout
    assert not (tmp_path / "l.jsonl").exists(), "a refused retraction still wrote to the ledger"


def test_the_retract_command_requires_a_reason_at_the_parser():
    """--reason is mandatory: forgetting it must be an error, not a silent unreasoned retraction."""
    import subprocess
    import sys

    from stop_guessing.version import repo_root

    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.main", "retract", "--claim", "C",
         "--field", "surface", "--removed", "x"],
        capture_output=True, text=True, cwd=str(repo_root()), timeout=300,
        stdin=subprocess.DEVNULL)
    assert res.returncode != 0
    assert "reason" in (res.stderr + res.stdout).lower()
