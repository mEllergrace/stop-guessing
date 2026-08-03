"""A vacuous proof must not be accepted.

This is the regression guard for #31, where mutation testing showed **all 21** procedures could be
replaced with `lambda: ProofResult(True)` and every claim still reported PROVEN. The proof system
recorded what a procedure said and had no notion of whether it did anything.

The mutation test is the test. If it ever passes for a mutant again, the harness has stopped being
evidence and become a formality.
"""

from __future__ import annotations

import pathlib

import pytest

from stop_guessing.ledger.chain import ChainKey
from stop_guessing.prove import runner, witness
from stop_guessing.prove.registry import REGISTRY, Procedure, ProofResult, all_procedures

yaml = pytest.importorskip("yaml")

KEY = ChainKey("mut", b"mutation-test-key-32-bytes-long!")


def _sandbox(tmp_path, monkeypatch):
    real = yaml.safe_load((runner.repo_root() / "docs" / "claims.yaml").read_text())
    claims = tmp_path / "claims.yaml"
    claims.write_text(yaml.safe_dump({
        "meta": {"version": "0.2.0"},
        "claims": [dict(c, proofs=[]) for c in real["claims"]],
    }))
    monkeypatch.setattr(runner, "CLAIMS", claims)
    return claims


@pytest.mark.parametrize("claim_id", sorted(all_procedures()))
def test_a_vacuous_procedure_is_rejected(claim_id, tmp_path, monkeypatch):
    """THE mutation test: swap in a procedure that executes nothing and claims success."""
    _sandbox(tmp_path, monkeypatch)
    old = REGISTRY[claim_id]
    monkeypatch.setitem(
        REGISTRY, claim_id,
        Procedure(claim_id, old.kind, lambda: ProofResult(True, ["I proved it"]), old.summary),
    )
    out = runner.run_one(claim_id, KEY, tmp_path / "l.jsonl")
    assert not out.passed, (
        f"{claim_id}: a procedure that executed nothing was accepted as a proof (#31)"
    )
    assert any("WITNESS" in o for o in out.observations)


@pytest.mark.parametrize("claim_id", sorted(all_procedures()))
def test_a_vacuous_proof_is_not_counted_even_if_recorded(claim_id, tmp_path, monkeypatch):
    """Belt and braces: `check()` must also reject it on re-verification, not only at write."""
    _sandbox(tmp_path, monkeypatch)
    ledger = tmp_path / "l.jsonl"
    old = REGISTRY[claim_id]
    monkeypatch.setitem(
        REGISTRY, claim_id,
        Procedure(claim_id, old.kind, lambda: ProofResult(True), old.summary),
    )
    runner.run_one(claim_id, KEY, ledger)
    row = next(r for r in runner.check(KEY, ledger)["rows"] if r["id"] == claim_id)
    assert not row["proven"]


# ── the witness itself ───────────────────────────────────────────────────────


def test_witness_records_modules_actually_entered():
    def real():
        from stop_guessing.ledger.chain import ChainKey as CK
        from stop_guessing.ledger.chain import append, verify
        log = []
        k = CK("k", b"k" * 32)
        for i in range(30):
            log = append(log, {"op": "x", "at": "t", "detail": str(i)}, k)
        verify(log, k)
        return ProofResult(True)

    _, w = witness.observe(real)
    assert "stop_guessing.ledger.chain" in w.modules
    assert w.calls > witness.MIN_CALLS
    assert not w.trivial


def test_witness_of_a_vacuous_function_is_empty():
    _, w = witness.observe(lambda: ProofResult(True))
    assert w.modules == set()
    assert w.trivial


def test_the_runner_modules_do_not_count_as_evidence():
    """Otherwise every procedure would clear the floor just by being called."""
    assert "stop_guessing.prove.runner" in witness.AMBIENT
    assert "stop_guessing.version" in witness.AMBIENT


def test_missing_witness_is_a_finding_not_a_pass():
    """A proof from before witnessing existed must not be silently honoured."""
    assert witness.check(None)
    assert "predates witnessing" in witness.check(None)[0]


def test_unavailable_witness_is_a_finding():
    findings = witness.check({"modules": [], "calls": 0, "unavailable": "RuntimeError: x"})
    assert findings and "unavailable" in findings[0]


def test_must_touch_rejects_a_proof_about_the_wrong_thing():
    w = {"modules": ["stop_guessing.caiq.fill"], "calls": 500, "unavailable": None}
    findings = witness.check(w, ["stop_guessing.ledger.chain"])
    assert any("never entered stop_guessing.ledger.chain" in f for f in findings)


def test_a_focused_single_module_proof_is_not_punished():
    """MIN_MODULES was briefly 2, which would have pushed procedures to touch extra code purely
    to clear the gate — optimising the measure rather than the thing."""
    w = {"modules": ["stop_guessing.ledger.chain"], "calls": 500, "unavailable": None}
    assert witness.check(w, ["stop_guessing.ledger.chain"]) == []


def test_must_touch_accepts_a_submodule():
    w = {"modules": ["stop_guessing.ledger.chain"], "calls": 500, "unavailable": None}
    assert witness.check(w, ["stop_guessing.ledger"]) == []


def test_subprocess_mode_requires_evidence_instead_of_modules():
    """A proof driving a child process legitimately runs nothing in-process."""
    w = {"modules": [], "calls": 0, "unavailable": None}
    assert witness.check(w, mode="subprocess", evidence={"cases": 73}) == []
    findings = witness.check(w, mode="subprocess", evidence={})
    assert findings and "recorded no evidence" in findings[0]


def test_every_claim_with_a_procedure_declares_must_touch_or_subprocess_mode():
    """A claim with neither has no witness gate beyond the trivia floor."""
    doc = yaml.safe_load(pathlib.Path(runner.CLAIMS).read_text())
    by_id = {c["id"]: c for c in doc["claims"]}
    weak = [
        cid for cid in all_procedures()
        if not by_id[cid].get("must_touch") and by_id[cid].get("witness_mode") != "subprocess"
    ]
    assert not weak, f"claims with no must_touch and no subprocess mode: {weak}"


def test_real_proofs_in_the_committed_ledger_carry_a_witness():
    """Every passing proof on record must have been witnessed."""
    led = pathlib.Path(runner.DEFAULT_LEDGER)
    if not led.is_file():
        pytest.skip("no local proof ledger")
    import json

    entries = [json.loads(x) for x in led.read_text().splitlines()]
    passing = [e for e in entries if e.get("op") == "proof.run" and e.get("passed")]
    if not passing:
        pytest.skip("no passing proofs recorded")
    latest = {}
    for e in passing:
        latest[e["claim"]] = e
    missing = [c for c, e in latest.items() if not e.get("witness")]
    assert not missing, f"passing proofs with no witness: {sorted(missing)}"


def test_witness_survives_a_procedure_that_raises():
    def boom():
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError):
        witness.observe(boom)
    # The profiler must be uninstalled even on the exception path, or every later test is traced.
    import sys

    assert sys.getprofile() is None
