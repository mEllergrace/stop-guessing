"""The judge panel: deferred disapproval, distinct lenses, declared non-independence."""

from __future__ import annotations

from stop_guessing.prove import judge
from stop_guessing.prove.registry import all_procedures, get


def _rec(calls=500, modules=3, evidence=None):
    return {"witness": {"calls": calls, "module_count": modules, "modules": ["m"] * modules,
                        "unavailable": None},
            "evidence": evidence if evidence is not None else {"x": 1}}


def test_a_procedure_with_no_failure_path_is_disapproved():
    def cannot_fail():
        return None

    p = judge.judge("C", cannot_fail, "live-run", _rec())
    v = next(v for v in p.verdicts if v.lens == "can-fail")
    assert v.verdict == judge.DEFER
    assert "cannot report a false claim" in v.reason


def test_the_independence_lens_always_dissents():
    for cid, proc in list(all_procedures().items())[:3]:
        p = judge.judge(cid, proc.fn, proc.kind, _rec())
        v = next(v for v in p.verdicts if v.lens == "independence")
        assert v.verdict == judge.DEFER
        assert v.independence == "none"


def test_disapproval_is_deferred_not_blocking():
    """The whole design: a lens makes a human look, it does not void a proof."""
    from stop_guessing.prove import runner

    src = __import__("inspect").getsource(runner.attest_self)
    assert "Deliberately NOT part of goal_met" in src


def test_lenses_are_distinct_not_repeated_votes():
    names = [lens(  "", "live-run", _rec()).lens for lens in judge.LENSES]
    assert len(names) == len(set(names)), "a repeated lens is a confident wrong answer"
    assert len(names) >= 6


def test_abstain_is_distinct_from_approve():
    v = judge.lens_adversarial_substance("", "live-run", _rec())
    assert v.verdict == judge.ABSTAIN, "not-applicable must not read as approval"


def test_no_evidence_is_disapproved():
    v = judge.lens_evidence_recorded("", "live-run", _rec(evidence={}))
    assert v.verdict == judge.DEFER


def test_thin_witness_is_disapproved_even_though_it_clears_the_floor():
    v = judge.lens_witness_breadth("", "live-run", _rec(calls=30))
    assert v.verdict == judge.DEFER


def test_a_broken_lens_abstains_rather_than_blocking():
    def exploding(src, kind, record):
        raise RuntimeError("lens is broken")

    original = judge.LENSES
    try:
        judge.LENSES = (*original, exploding)
        p = judge.judge("C", get(next(iter(all_procedures()))).fn, "live-run", _rec())
        assert any(v.verdict == judge.ABSTAIN and "raised" in v.reason for v in p.verdicts)
    finally:
        judge.LENSES = original


def test_the_disclosure_states_there_is_no_independence():
    assert "Independence: NONE" in judge.PANEL_DISCLOSURE
    assert "not evidence of adequacy" in judge.PANEL_DISCLOSURE


def test_summarise_groups_by_lens():
    panels = [judge.judge(cid, p.fn, p.kind, _rec())
              for cid, p in list(all_procedures().items())[:4]]
    s = judge.summarise(panels)
    assert s["claims_judged"] == 4
    assert s["deferred_disapprovals"] >= 4  # independence alone
    assert "independence" in s["by_lens"]
    assert "Independence: NONE" in s["disclosure"]


def test_every_real_proof_carries_a_judge_panel():
    import json
    import pathlib

    from stop_guessing.prove import runner

    led = pathlib.Path(runner.DEFAULT_LEDGER)
    if not led.is_file():
        return
    passing = [json.loads(x) for x in led.read_text().splitlines()]
    passing = [e for e in passing if e.get("op") == "proof.run" and e.get("passed")]
    if not passing:
        return
    latest = {}
    for e in passing:
        latest[e["claim"]] = e
    missing = [c for c, e in latest.items() if not e.get("judge")]
    assert not missing, f"passing proofs with no judge panel: {sorted(missing)}"
