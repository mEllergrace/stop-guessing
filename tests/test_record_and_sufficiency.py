"""M2: the custody record's three tiers, and the sufficiency gate.

The distinction under test throughout: an empty list is a positive assertion, an absent key is
"nobody looked". Conflating them is how a ledger overclaims without anyone lying — and it was a
real bug here, caught by CLAIM-06's proof procedure failing rather than by a test.
"""

from __future__ import annotations

import pytest

from stop_guessing.attest import dsse
from stop_guessing.ledger.entry import (
    OPS,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    CustodyRecord,
    RecordInvalid,
    dig,
    strength,
    validate_tier_a,
    validate_tier_b,
)
from stop_guessing.verify.sufficiency import ASSERTION_PATHS, QUESTIONS, REGIMES, assess

BASE = dict(
    op="artifact.read", agent_id="spiffe://local/t/agent/main", runtime_action_id="toolu_1",
    operator={"identity": "t", "uid": 1}, session_id="s1", posture="steer", outcome="allow",
    channel="hookSpecificOutput.permissionDecision", at="t", recorded_at="t", record_id="sg:1",
    input_digest="sha256:x", policy_set_digest="sha256:y", determining_policy="10-base#allow",
)


def _full():
    """A record populated well enough to certify AND to answer every governance question.

    Note `actor.acted_on_behalf_of.prompt_id` is distinct from `lifecycle.prompt_id`: the first
    is the root of the IAM-AG-03 delegation chain (which human request authorised this), the
    second is session correlation. Tier B requires the former.
    """
    return CustodyRecord(**BASE, extra={
        "actor": {"acted_on_behalf_of": {"prompt_id": "prm_1", "human_id": "mailto:x",
                                         "delegation_depth": 0}},
        "authority": {"capability": {"grant_id": "c1", "scope": ["read:project"]}},
        "decision": {"basis": {"taint_labels": [], "taint_depth": 0}},
        "resources": {"used": [{"artifact_id": "a1", "digest": "sha256:z"}]},
        "lifecycle": {"prompt_id": "prm_1"},
    }).build()


# ── envelope ─────────────────────────────────────────────────────────────────


def test_statement_is_in_toto_shaped():
    s = CustodyRecord(**BASE).build(subjects=[{"name": "f", "digest": {"sha256": "0" * 64}}])
    assert s["_type"] == STATEMENT_TYPE
    assert s["predicateType"] == PREDICATE_TYPE
    assert s["subject"][0]["digest"]["sha256"]


def test_subjects_default_to_empty_not_missing():
    assert CustodyRecord(**BASE).build()["subject"] == []


# ── Tier A ───────────────────────────────────────────────────────────────────


def test_valid_record_builds():
    assert CustodyRecord(**BASE).build()["predicate"]["action"]["op"] == "artifact.read"


def test_empty_alterations_is_accepted_as_an_assertion():
    assert CustodyRecord(**BASE).build()["predicate"]["alterations"] == []


def test_absent_alterations_is_rejected():
    pred = CustodyRecord(**BASE).predicate()
    del pred["alterations"]
    assert any("alterations" in m for m in validate_tier_a(pred))


def test_absent_known_gaps_is_rejected():
    pred = CustodyRecord(**BASE).predicate()
    del pred["verification"]["known_gaps"]
    assert any("known_gaps" in m for m in validate_tier_a(pred))


def test_alterations_must_be_a_list_not_a_string():
    pred = CustodyRecord(**BASE).predicate()
    pred["alterations"] = "none"
    assert any("must be a list" in m for m in validate_tier_a(pred))


@pytest.mark.parametrize(("field_", "bad"), [
    ("op", "not.a.real.op"), ("outcome", "probably"), ("posture", "relaxed"),
    ("method_kind", "vibes"),
])
def test_controlled_vocabularies_are_enforced(field_, bad):
    with pytest.raises(RecordInvalid):
        CustodyRecord(**{**BASE, field_: bad}).build()


def test_error_names_every_missing_field_not_just_the_first():
    exc = RecordInvalid(validate_tier_a({}))
    assert len(exc.missing) >= 15
    assert "action.op (absent)" in exc.missing


def test_proof_run_is_in_the_op_vocabulary():
    """The ledger records its own proofs, so `proof.run` must be a first-class op."""
    assert "proof.run" in OPS


# ── Tier B ───────────────────────────────────────────────────────────────────


def test_tier_b_blocks_certification_not_writing():
    rec = CustodyRecord(**BASE).build()
    assert rec["predicate"]
    assert validate_tier_b(rec["predicate"]), "a thin record should be uncertifiable"


def test_full_record_passes_tier_b():
    assert validate_tier_b(_full()["predicate"]) == []


def test_data_touching_op_requires_resources_used():
    pred = CustodyRecord(**BASE).predicate()
    assert any("resources.used" in f for f in validate_tier_b(pred))


def test_delegated_script_requires_a_passing_test():
    pred = CustodyRecord(**{**BASE, "method_kind": "delegated-script"}, extra={
        "action": {"method": {"script": {"test_result": {"passed": False}}}},
        "resources": {"used": [{"artifact_id": "a"}]},
    }).predicate()
    assert any("test_result.passed" in f for f in validate_tier_b(pred))


def test_delegation_depth_requires_a_chain():
    pred = CustodyRecord(**BASE, extra={
        "actor": {"acted_on_behalf_of": {"prompt_id": "p", "delegation_depth": 2}},
    }).predicate()
    assert any("delegation_chain" in f for f in validate_tier_b(pred))


def test_observe_posture_does_not_require_a_prompt_id():
    pred = CustodyRecord(**{**BASE, "posture": "observe"}).predicate()
    assert not any("prompt_id" in f for f in validate_tier_b(pred))


# ── Tier C / strength ────────────────────────────────────────────────────────


def test_strength_reports_the_floor():
    assert strength(CustodyRecord(**BASE).predicate()) == "chain-keyed"
    assert strength(CustodyRecord(**{**BASE, "chain": {"algo": "sha256"}}).predicate()) \
        == "chain-only"


def test_isolation_raises_strength():
    pred = CustodyRecord(**BASE, extra={
        "verification": {"recorder": {"isolation_tier": 2}}}).predicate()
    assert strength(pred) == "chain-keyed+isolated"


# ── sufficiency ──────────────────────────────────────────────────────────────


def test_there_are_eight_regimes():
    assert len(REGIMES) == 8


def test_empty_ledger_answers_nothing():
    r = assess([])
    assert r["verdict"] == "incomplete"
    assert all(not v["answerable"] for v in r["questions"].values())


def test_tier_a_valid_but_thin_record_is_incomplete_not_sufficient():
    """The DEMM-Bench overclaim, refused: a schema-valid record is not evidence."""
    r = assess([CustodyRecord(**BASE).build()])
    assert r["verdict"] == "incomplete"
    assert r["answerable"] == 0


def test_full_record_is_sufficient():
    r = assess([_full()])
    assert r["verdict"] == "sufficient"
    assert r["answerable"] == len(QUESTIONS)


def test_incomplete_names_the_blocking_regime():
    r = assess([CustodyRecord(**BASE).build()])
    q = r["questions"]["what data was touched, and where did it go"]
    assert "resource_touch" in q["blocked_by"]


def test_empty_known_gaps_counts_as_populated():
    """Regression: `known_gaps: []` asserts "nothing skipped" and must not read as a gap.

    Caught in the field by CLAIM-06's proof procedure returning passed=False, not by a test.
    """
    assert "verification.known_gaps" in ASSERTION_PATHS
    r = assess([_full()])
    assert r["regimes"]["verification"]["fully_populated"]


def test_one_thin_record_spoils_the_batch():
    """Sufficiency is per-ledger; a single unpopulated record blocks the claim."""
    r = assess([_full(), CustodyRecord(**BASE).build()])
    assert r["verdict"] == "incomplete"


def test_assess_accepts_bare_predicates_and_full_statements():
    a = assess([_full()])
    b = assess([_full()["predicate"]])
    assert a["verdict"] == b["verdict"] == "sufficient"


# ── DSSE ─────────────────────────────────────────────────────────────────────


def test_dsse_roundtrip():
    stmt = _full()
    env = dsse.sign(stmt, b"k" * 32, "kid-1")
    ok, why = dsse.verify(env, b"k" * 32)
    assert ok, why
    assert dsse.payload_of(env) == stmt


def test_dsse_rejects_a_wrong_key():
    env = dsse.sign(_full(), b"k" * 32, "kid-1")
    ok, why = dsse.verify(env, b"j" * 32)
    assert not ok and "no signature verified" in why


def test_dsse_rejects_a_modified_payload():
    import base64
    import json

    env = dsse.sign(_full(), b"k" * 32, "kid-1")
    stmt = json.loads(base64.b64decode(env["payload"]))
    stmt["predicate"]["decision"]["outcome"] = "deny"
    env["payload"] = base64.b64encode(dsse.canonical(stmt)).decode()
    assert not dsse.verify(env, b"k" * 32)[0]


def test_dsse_pae_lengths_prevent_field_confusion():
    """Without length prefixes, a payload could be reinterpreted as a different type."""
    assert dsse.pae("a", b"bc") == b"DSSEv1 1 a 2 bc"
    assert dsse.pae("ab", b"c") != dsse.pae("a", b"bc")


def test_dsse_malformed_envelope_is_a_finding_not_a_crash():
    ok, why = dsse.verify({"nope": 1}, b"k" * 32)
    assert not ok and "malformed" in why


def test_dsse_empty_signature_list_is_rejected():
    env = dsse.sign(_full(), b"k" * 32, "kid")
    env["signatures"] = []
    assert not dsse.verify(env, b"k" * 32)[0]


def test_dig_distinguishes_absent_from_none():
    assert dig({"a": None}, "a") == (True, None)
    assert dig({}, "a") == (False, None)
