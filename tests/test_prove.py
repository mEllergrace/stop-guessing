"""The goal machinery: proofs are ledger records, and the gate can fail.

A gate that cannot fail is not a gate, so most of these tests are the failure modes.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.ledger.chain import ChainKey
from stop_guessing.ledger.sink import record
from stop_guessing.prove import runner
from stop_guessing.prove.registry import (
    REGISTRY,
    Procedure,
    ProofResult,
    all_procedures,
    get,
)

yaml = pytest.importorskip("yaml")

KEY = ChainKey("t", b"proof-test-key-32-bytes-long!!!!")


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """A claims file and ledger of our own, so tests never touch the real ones."""
    claims = tmp_path / "claims.yaml"
    claims.write_text(yaml.safe_dump({
        "meta": {"version": "0.1.0"},
        "claims": [
            {"id": "CLAIM-02", "statement": "s", "proof_kind": "adversarial",
             "milestone": "M1", "aicm": ["LOG-10"], "proofs": []},
            {"id": "CLAIM-99", "statement": "s", "proof_kind": "live-run",
             "milestone": "M9", "aicm": ["X-01"], "proofs": []},
        ],
    }), encoding="utf-8")
    monkeypatch.setattr(runner, "CLAIMS", claims)
    return claims, tmp_path / "proofs.jsonl"


# ── the contract ─────────────────────────────────────────────────────────────


def test_every_registered_procedure_declares_a_kind_matching_its_claim():
    """A claim declared `adversarial` must not be satisfied by a happy-path procedure."""
    doc = yaml.safe_load(runner.CLAIMS.read_text(encoding="utf-8"))
    declared = {c["id"]: c["proof_kind"] for c in doc["claims"]}
    for cid, proc in all_procedures().items():
        assert cid in declared, f"{cid} has a procedure but no claim"
        assert proc.kind == declared[cid], (
            f"{cid}: procedure kind {proc.kind!r} != declared {declared[cid]!r}"
        )


def test_procedures_exist_for_landed_milestones():
    assert {"CLAIM-02", "CLAIM-03", "CLAIM-04"} <= set(all_procedures())


def test_procedure_source_digest_changes_with_its_source():
    p = get("CLAIM-02")
    assert p is not None
    assert len(p.source_digest()) == 64


def test_procedures_are_frozen_so_nothing_can_swap_its_own_prover():
    p = get("CLAIM-02")
    with pytest.raises(Exception, match="cannot assign"):
        p.fn = lambda: ProofResult(True)


def test_proof_ref_is_derived_from_seq_and_hash():
    assert runner.proof_ref({"seq": 7, "hash": "abcdef0123456789ff"}) == "sg:7:abcdef0123456789"


# ── running ──────────────────────────────────────────────────────────────────


def test_a_passing_run_writes_a_ref_back(sandbox):
    claims, ledger = sandbox
    out = runner.run_one("CLAIM-02", KEY, ledger)
    assert out.passed and out.ref
    doc = yaml.safe_load(claims.read_text())
    c = next(c for c in doc["claims"] if c["id"] == "CLAIM-02")
    assert c["proofs"] == [out.ref]
    assert "last_proved" in c


def test_the_ref_resolves_to_a_real_ledger_record(sandbox):
    _, ledger = sandbox
    out = runner.run_one("CLAIM-02", KEY, ledger)
    entries = [json.loads(x) for x in ledger.read_text().splitlines()]
    assert runner.proof_ref(entries[0]) == out.ref
    assert entries[0]["claim"] == "CLAIM-02"
    assert entries[0]["passed"] is True
    assert entries[0]["op"] == "proof.run"


def _swap(monkeypatch, cid, fn):
    """Replace a procedure wholesale.

    `Procedure` is frozen on purpose — a procedure that could be reassigned at runtime would let
    the thing being proved choose its own prover — so the whole entry is swapped instead.
    """
    all_procedures()  # force registration
    old = REGISTRY[cid]
    monkeypatch.setitem(REGISTRY, cid, Procedure(cid, old.kind, fn, old.summary))


def test_a_failing_procedure_records_but_does_not_write_back(sandbox, monkeypatch):
    claims, ledger = sandbox
    _swap(monkeypatch, "CLAIM-02", lambda: ProofResult(False, ["nope"]))
    out = runner.run_one("CLAIM-02", KEY, ledger)
    assert not out.passed
    doc = yaml.safe_load(claims.read_text())
    assert next(c for c in doc["claims"] if c["id"] == "CLAIM-02")["proofs"] == []


def test_a_crashing_procedure_is_a_finding_not_a_stack_trace(sandbox, monkeypatch):
    _, ledger = sandbox

    def boom():
        raise RuntimeError("procedure exploded")

    _swap(monkeypatch, "CLAIM-02", boom)
    out = runner.run_one("CLAIM-02", KEY, ledger)
    assert not out.passed
    assert any("raised" in o for o in out.observations)


def test_unknown_claim_is_not_silently_ok(sandbox):
    _, ledger = sandbox
    out = runner.run_one("CLAIM-NOPE", KEY, ledger)
    assert not out.passed and out.ref is None


# ── the gate's failure modes ─────────────────────────────────────────────────


def test_gate_is_red_while_any_claim_is_unproven(sandbox):
    _, ledger = sandbox
    runner.run_one("CLAIM-02", KEY, ledger)
    result = runner.check(KEY, ledger)
    assert not result["ok"]
    assert "CLAIM-99" in result["unproven"]


def test_hand_edited_ref_is_rejected(sandbox):
    """The forbidden move: typing a real record id onto a different claim."""
    claims, ledger = sandbox
    out = runner.run_one("CLAIM-02", KEY, ledger)
    doc = yaml.safe_load(claims.read_text())
    next(c for c in doc["claims"] if c["id"] == "CLAIM-99")["proofs"] = [out.ref]
    claims.write_text(yaml.safe_dump(doc))
    row = next(r for r in runner.check(KEY, ledger)["rows"] if r["id"] == "CLAIM-99")
    assert not row["proven"]
    assert any("recorded against CLAIM-02" in d for d in row["dead"])


def test_invented_ref_is_rejected(sandbox):
    claims, ledger = sandbox
    runner.run_one("CLAIM-02", KEY, ledger)
    doc = yaml.safe_load(claims.read_text())
    next(c for c in doc["claims"] if c["id"] == "CLAIM-99")["proofs"] = ["sg:42:deadbeefdeadbeef"]
    claims.write_text(yaml.safe_dump(doc))
    row = next(r for r in runner.check(KEY, ledger)["rows"] if r["id"] == "CLAIM-99")
    assert not row["proven"]
    assert any("not found in the ledger" in d for d in row["dead"])


def test_tampering_with_a_proof_record_fails_everything(sandbox):
    _, ledger = sandbox
    runner.run_one("CLAIM-02", KEY, ledger)
    lines = ledger.read_text().splitlines()
    d = json.loads(lines[0])
    d["passed"] = True
    d["observations"] = ["I definitely proved this"]
    lines[0] = json.dumps(d, sort_keys=True, separators=(",", ":"))
    ledger.write_text("\n".join(lines) + "\n")
    result = runner.check(KEY, ledger)
    assert not result["chain_intact"]
    assert not result["ok"]
    assert result["proven"] == 0, "a broken chain must invalidate every proof in it"


def test_proof_from_a_since_modified_procedure_is_rejected(sandbox, monkeypatch):
    _, ledger = sandbox
    runner.run_one("CLAIM-02", KEY, ledger)
    assert runner.check(KEY, ledger)["rows"][0]["proven"]
    _swap(monkeypatch, "CLAIM-02", lambda: ProofResult(True))
    row = next(r for r in runner.check(KEY, ledger)["rows"] if r["id"] == "CLAIM-02")
    assert not row["proven"]
    assert any("since-modified procedure" in d for d in row["dead"])


def test_unkeyed_ledger_does_not_yield_keyed_verification(sandbox):
    _, ledger = sandbox
    record(ledger, {"op": "proof.run", "claim": "CLAIM-02", "passed": True, "at": "t"}, None)
    assert not runner.check(None, ledger)["chain_keyed"]


# ── the goal ─────────────────────────────────────────────────────────────────


def test_goal_is_not_met_before_the_caiq_is_filled(sandbox, tmp_path):
    """Hermetic: an empty caiq dir of its own, not the repo's real one.

    This test previously read `docs/ai-caiq/` directly and started passing for the wrong reason
    the moment the real workbook was generated. A test that reads production state is not a test.
    """
    _, ledger = sandbox
    empty_caiq = tmp_path / "caiq"
    empty_caiq.mkdir()
    runner.run_one("CLAIM-02", KEY, ledger)
    result = runner.attest_self(KEY, ledger, caiq_dir=empty_caiq)
    assert not result["goal_met"]
    assert not result["caiq"]["filled_from_proofs"]
    assert result["caiq"]["filled_workbooks"] == []


def test_attestation_maps_proven_claims_to_aicm_controls(sandbox, tmp_path):
    _, ledger = sandbox
    runner.run_one("CLAIM-02", KEY, ledger)
    result = runner.attest_self(KEY, ledger, caiq_dir=tmp_path / "empty")
    assert result["aicm_controls_evidenced"].get("LOG-10") == ["CLAIM-02"]


def test_unproven_claims_contribute_no_control_evidence(sandbox, tmp_path):
    _, ledger = sandbox
    result = runner.attest_self(KEY, ledger, caiq_dir=tmp_path / "empty")
    assert result["aicm_controls_evidenced"] == {}
