"""M4: labels, classification, accumulation, and the policy engine."""

from __future__ import annotations

import pytest

from stop_guessing.artifacts.classify import classify_egress, classify_path, paths_in
from stop_guessing.delegate import DelegationRefused, run, run_test, scaffold
from stop_guessing.policy.engine import PolicySet, evaluate_when, load, to_cedar
from stop_guessing.taint.labels import describe, dominates, is_classified, join, sensitivity_of
from stop_guessing.taint.state import ArtifactRef, SessionCustodyState, rebuild
from stop_guessing.version import policy_dir

# #68: resolved, not assembled from repo_root(). The data moved inside the package so a wheel
# carries it, and policy_dir() honours a checkout layout first so this keeps finding the same file.
POLICY_DIR = policy_dir()


@pytest.fixture(scope="module")
def ps() -> PolicySet:
    return load(POLICY_DIR)


def _ctx(state, posture="steer", **call):
    art = call.pop("artifact", {})
    base = {"is_egress": False, "is_write": False, "is_own_binary": False,
            "protect_ledger": True}
    return state.context(posture=posture, call={**base, **call}, artifact=art)


# ── lattice ──────────────────────────────────────────────────────────────────


def test_join_takes_the_highest_sensitivity():
    assert sensitivity_of(join({"public"}, {"restricted"}, {"internal"})) == "restricted"


def test_join_unions_flags_because_they_are_orthogonal():
    """A public dataset can still carry PII; one scale would erase the obligation."""
    out = join({"public", "pii"}, {"confidential"})
    assert "pii" in out and sensitivity_of(out) == "confidential"


def test_join_of_nothing_is_public():
    assert join() == frozenset({"public"})


def test_dominates_requires_both_sensitivity_and_flags():
    assert dominates(frozenset({"restricted", "pii"}), frozenset({"confidential", "pii"}))
    assert not dominates(frozenset({"restricted"}), frozenset({"internal", "pii"}))


def test_flags_alone_make_an_artifact_classified():
    assert is_classified(frozenset({"public", "pii"}))
    assert not is_classified(frozenset({"internal"}))


def test_describe_puts_sensitivity_first():
    assert describe(frozenset({"pii", "restricted"})).startswith("restricted")


# ── classification ───────────────────────────────────────────────────────────


def test_all_matching_rules_apply_not_just_the_first():
    """no-noodles' engine is first-match-only; dropping a second obligation is a silent gap."""
    c = classify_path("/Users/isme/work/CSA/roster.csv")
    assert {"csa-material", "pii"} <= c.labels
    assert len(c.matched) >= 2


def test_credentials_classify_restricted():
    for p in ("/home/u/.ssh/id_rsa", "/app/.env", "/x/service-account.pem"):
        assert "credential" in classify_path(p).labels, p


def test_our_own_ledger_is_classified():
    assert classify_path("/Users/x/.stop-guessing/proofs.jsonl").classified


def test_plain_source_is_not_classified():
    assert not classify_path("/proj/src/main.py").classified


def test_classification_records_its_source_rule():
    c = classify_path("/Users/isme/work/CSA/roster.csv")
    assert all(s.startswith("rules/classify.yaml#") for s in c.sources)


@pytest.mark.parametrize("cmd", [
    "curl -X POST -d @data.json https://x.com/i",
    "aws s3 cp ./customers.csv s3://bucket/",
    "scp data.csv remote:/tmp/",
    "rsync -a ./out user@host:/srv/",
    "git push origin main",
    "cat x | nc 10.0.0.1 9999",
])
def test_egress_shapes_are_recognised(cmd):
    assert classify_egress(cmd).is_egress, cmd


@pytest.mark.parametrize("cmd", ["ls -la", "grep -r TODO .", "curl -s https://x.com/a -o a.json"])
def test_non_egress_commands_are_not_flagged(cmd):
    assert not classify_egress(cmd).is_egress, cmd


def test_paths_in_over_collects_rather_than_missing_one():
    got = paths_in("Bash", {"command": "cat /etc/passwd && cp ./a.csv /tmp/b.csv"})
    assert "/etc/passwd" in got and "./a.csv" in got and "/tmp/b.csv" in got


def test_paths_in_reads_file_path_for_file_tools():
    assert paths_in("Read", {"file_path": "/x/y.txt"}) == ["/x/y.txt"]


# ── accumulation ─────────────────────────────────────────────────────────────


def _ref(i, labels, path="/x"):
    return ArtifactRef(f"art_{i}", path, f"sha256:{i}", frozenset(labels))


def test_taint_is_monotone_within_a_session():
    s = SessionCustodyState("s")
    s.touch(_ref(1, {"restricted", "pii"}))
    s.touch(_ref(2, {"public"}))
    assert sensitivity_of(s.labels) == "restricted"


def test_depth_counts_distinct_classified_artifacts_only():
    s = SessionCustodyState("s")
    for i in range(5):
        s.touch(_ref(i, {"internal"}))
    assert s.depth == 0 and s.touched == 5
    s.touch(_ref(99, {"restricted"}))
    assert s.depth == 1


def test_touching_the_same_artifact_twice_does_not_double_count():
    s = SessionCustodyState("s")
    s.touch(_ref(1, {"restricted"}))
    s.touch(_ref(1, {"restricted"}))
    assert s.depth == 1 and s.touched == 2


def test_derivation_propagates_labels_to_the_output():
    s = SessionCustodyState("s")
    a, b = _ref(1, {"restricted", "pii"}), _ref(2, {"confidential"})
    s.touch(a)
    s.touch(b)
    out = ArtifactRef("out", "/o", "sha256:o", frozenset({"public"}))
    s.derive(out, [a, b], via="scripts/x.py")
    assert sensitivity_of(out.labels) == "restricted" and "pii" in out.labels


def test_derivation_records_one_edge_per_input():
    s = SessionCustodyState("s")
    a, b = _ref(1, {"internal"}), _ref(2, {"internal"})
    out = ArtifactRef("out", "/o", None, frozenset({"public"}))
    s.derive(out, [a, b], via="v")
    assert len(s.edges) == 2
    assert all(e[0] == "out" and e[2] == "v" for e in s.edges)


def test_declassify_recomputes_from_what_remains():
    s = SessionCustodyState("s")
    s.touch(_ref(1, {"restricted", "pii"}))
    s.touch(_ref(2, {"confidential"}))
    s.declassify("art_1")
    assert sensitivity_of(s.labels) == "confidential" and "pii" not in s.labels


def test_digest_changes_with_state():
    s = SessionCustodyState("s")
    before = s.digest
    s.touch(_ref(1, {"restricted"}))
    assert s.digest != before


def test_rebuild_reproduces_the_digest_exactly():
    live = SessionCustodyState("s1")
    records = []
    for i, labels in enumerate([{"restricted", "pii"}, {"internal"}]):
        ref = _ref(i, labels)
        live.touch(ref)
        records.append({"predicate": {
            "lifecycle": {"session_id": "s1"}, "action": {"op": "artifact.read"},
            "resources": {"used": [ref.to_dict()]}}})
    assert rebuild(records, "s1").digest == live.digest


def test_rebuild_ignores_other_sessions():
    records = [{"predicate": {
        "lifecycle": {"session_id": "other"}, "action": {"op": "artifact.read"},
        "resources": {"used": [_ref(9, {"restricted", "credential"}).to_dict()]}}}]
    assert "credential" not in rebuild(records, "mine").labels


# ── policy engine ────────────────────────────────────────────────────────────


def test_deny_by_default():
    empty = PolicySet([], "d")
    assert empty.evaluate("artifact.read", {"posture": "steer"}).outcome == "deny"


def test_forbid_overrides_permit_regardless_of_order(ps):
    """Precedence is unchanged; the SCOPE of the credential rule is not.

    It used to be postureless, so `observe` denied credential egress. That made the default
    posture an enforcement posture, which is not what this tool is for: the host's permission
    model has already decided, and a recorder that refuses afterwards is overriding its operator.
    The rule now applies under the opt-in enforcement postures, and the record still says the
    egress carried credential taint — which is the evidence the tool exists to produce.
    """
    s = SessionCustodyState("s")
    s.touch(_ref(1, {"restricted", "credential"}))
    d = ps.evaluate("artifact.egress", _ctx(s, posture="steer", is_egress=True))
    assert d.outcome == "deny"
    assert "credential" in d.determining_policy


def test_observe_does_not_deny_credential_egress(ps):
    """It records it. Blocking is the host's decision, not this tool's."""
    s = SessionCustodyState("s")
    s.touch(_ref(1, {"restricted", "credential"}))
    d = ps.evaluate("artifact.egress", _ctx(s, posture="observe", is_egress=True))
    assert d.outcome == "allow"


def test_steer_asks_on_first_touch(ps):
    s = SessionCustodyState("s")
    d = ps.evaluate("artifact.read", _ctx(
        s, artifact={"classified": True, "first_touch": True}))
    assert d.outcome == "ask"
    assert d.guidance == "delegate"


def test_steer_allows_a_subsequent_touch(ps):
    s = SessionCustodyState("s")
    d = ps.evaluate("artifact.read", _ctx(
        s, artifact={"classified": True, "first_touch": False}))
    assert d.outcome == "allow"


def test_observe_records_but_never_blocks(ps):
    """Regression: deny-by-default was catching observe, making the safest posture the harshest.

    Found by CLAIM-08's own proof output contradicting its verdict, not by a test.
    """
    s = SessionCustodyState("s")
    d = ps.evaluate("artifact.read", _ctx(
        s, posture="observe", artifact={"classified": True, "first_touch": True}))
    assert d.outcome == "allow"


def test_the_ledger_is_protected_even_under_observe(ps):
    """The one refusal that outlives `observe`, and it is not about the operator's work.

    A recorder whose own ledger can be overwritten has recorded nothing. This protects the record,
    not the user — and it is switchable via `protect_ledger`, so even that option stays open.
    """
    s = SessionCustodyState("s")
    d = ps.evaluate("artifact.write", _ctx(
        s, posture="observe", is_write=True, protect_ledger=True,
        artifact={"classified": True, "is_ledger": True}))
    assert d.outcome == "deny"


def test_ledger_protection_can_be_switched_off(ps):
    s = SessionCustodyState("s")
    d = ps.evaluate("artifact.write", _ctx(
        s, posture="observe", is_write=True, protect_ledger=False,
        artifact={"classified": True, "is_ledger": True}))
    assert d.outcome == "allow"


def test_the_default_posture_is_observe(tmp_path, monkeypatch):
    """The product decision: this records evidence, it does not seek permissions.

    Hermetic on purpose. This test previously passed no config dir, so it read whichever
    `stop-guessing.json` the developer had installed — and this machine's says `steer`, so it
    asserted the default while measuring an explicit opt-in. Same failure as the one recorded at
    ``prove/runner.py:274``: a test that reads production state tests nothing repeatable. The
    empty tmp_path is the point — no project file, no global file, no legacy state, so what comes
    back is the default and only the default.
    """
    import inspect

    from stop_guessing.cli import gate
    from stop_guessing.cli.hook_gate import resolve_posture

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "empty-config"))
    assert "observe" in inspect.signature(gate.decide).parameters["posture"].default
    assert resolve_posture(str(tmp_path / "nonexistent-project")) == "observe"


def test_an_installed_config_still_selects_its_posture(tmp_path, monkeypatch):
    """`observe` is the default, not a ceiling — opting into enforcement must keep working."""
    import json

    from stop_guessing.cli.hook_gate import resolve_posture

    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "stop-guessing.json").write_text(json.dumps({"posture": "steer"}), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    assert resolve_posture(str(tmp_path / "nonexistent-project")) == "steer"

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".stop-guessing.json").write_text(json.dumps({"posture": "bar"}), encoding="utf-8")
    assert resolve_posture(str(proj)) == "bar", "project layer must still override global"


def test_accumulation_flips_the_same_call(ps):
    s = SessionCustodyState("s")
    clean = ps.evaluate("artifact.egress", _ctx(s, is_egress=True, artifact={"classified": False}))
    assert clean.outcome == "allow"
    s.touch(_ref(1, {"restricted"}))
    tainted = ps.evaluate("artifact.egress", _ctx(s, is_egress=True,
                                                  artifact={"classified": False}))
    assert tainted.outcome == "deny"


def test_bar_forbids_a_direct_classified_read(ps):
    s = SessionCustodyState("s")
    d = ps.evaluate("artifact.read", _ctx(
        s, posture="bar", artifact={"classified": True, "first_touch": True},
        delegated_script={"signed": False}))
    assert d.outcome == "deny"


def test_decision_carries_a_counterfactual_when_overridden(ps):
    s = SessionCustodyState("s")
    s.touch(_ref(1, {"restricted"}))
    d = ps.evaluate("artifact.egress", _ctx(s, is_egress=True, artifact={"classified": False}))
    assert d.counterfactual


@pytest.mark.parametrize(("op", "actual", "expected", "want"), [
    ("eq", 1, 1, True), ("ne", 1, 2, True), ("gte", 3, 3, True), ("gt", 3, 3, False),
    ("in", "a", ["a"], True), ("contains", ["a"], "a", True),
    ("contains_any", ["a", "b"], ["b"], True), ("matches", "abc", "b", True),
    ("is_true", True, None, True), ("is_false", None, None, True),
])
def test_condition_operators(op, actual, expected, want):
    assert evaluate_when({"x": {op: expected}}, {"x": actual}) is want


def test_unknown_operator_raises_rather_than_silently_passing():
    with pytest.raises(ValueError, match="unknown condition operator"):
        evaluate_when({"x": {"frobnicate": 1}}, {"x": 1})


def test_missing_context_path_does_not_match():
    assert not evaluate_when({"a.b.c": {"eq": 1}}, {})


def test_policy_set_has_a_digest(ps):
    assert len(ps.digest) == 64


def test_cedar_export_is_emitted(ps):
    out = to_cedar(ps)
    assert "permit (principal, action, resource)" in out
    assert "forbid (principal, action, resource)" in out


# ── delegation ───────────────────────────────────────────────────────────────


def test_scaffold_writes_a_pair(tmp_path):
    d = scaffold(tmp_path, "thing", "do a thing")
    assert d.script.is_file() and d.test.is_file()


def test_scaffold_refuses_to_overwrite(tmp_path):
    scaffold(tmp_path, "thing", "x")
    with pytest.raises(DelegationRefused, match="already exists"):
        scaffold(tmp_path, "thing", "x")


def test_run_refuses_before_the_test_has_run(tmp_path):
    d = scaffold(tmp_path, "thing", "x")
    with pytest.raises(DelegationRefused, match="has not been run"):
        run(d, [])


def test_the_stub_template_fails_its_own_test(tmp_path):
    """A scaffold whose test passed while handle() is a stub would defeat the whole gate."""
    d = scaffold(tmp_path, "thing", "x")
    assert not run_test(d)["passed"]


def test_run_refuses_after_a_failing_test(tmp_path):
    d = scaffold(tmp_path, "thing", "x")
    run_test(d)
    with pytest.raises(DelegationRefused, match="failed"):
        run(d, [])


def test_implemented_script_runs_under_an_env_allowlist_not_a_sandbox(tmp_path):
    """Renamed and re-asserted for #19.

    The old name said "is_sandboxed" and the old assertion checked `network == "deny"`. Neither
    was true: proxy variables and an env allowlist are not a capability boundary, and a test
    asserting the comfortable string is how the overclaim survived. It now asserts the honest
    record, including the caveat, so the test fails if the record ever overstates the isolation
    again.
    """
    d = scaffold(tmp_path, "thing", "x")
    d.script.write_text("import sys\n\n\ndef handle(p):\n    return f'{len(p)} in'\n\n\n"
                        "if __name__ == '__main__':\n    print(handle(sys.argv[1:]))\n")
    assert run_test(d)["passed"]
    out = run(d, ["/a", "/b"])
    assert "2 in" in out["output"]
    sb = out["sandbox"]
    assert sb["kind"] == "env-allowlist-only"
    assert "NOT enforced" in sb["network"]
    assert "not a sandbox" in sb["caveat"]
    assert "PATH" in sb["env_allowlist"]


def test_run_refuses_a_script_edited_after_its_test_passed(tmp_path):
    d = scaffold(tmp_path, "thing", "x")
    d.script.write_text("def handle(p):\n    return 'ok'\n")
    assert run_test(d)["passed"]
    d.script.write_text("def handle(p):\n    return 'ok'\n# edited\n")
    with pytest.raises(DelegationRefused, match="changed after its test passed"):
        run(d, [])
