"""Direct tests for security-relevant functions that only had indirect coverage.

A coverage review found 46 public symbols not named in any test, proof or CLI path. Most are
dataclasses exercised through the functions that return them, which is fine. These are the ones
where indirect coverage is not good enough — the seal MAC and the guard sub-checks are the newest
security-bearing code in the repo, and `record_many` writes to the ledger.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from stop_guessing.artifacts.classify import load_rules, ruleset_digest
from stop_guessing.artifacts.identity import artifact_id, canonical_path, identify
from stop_guessing.ledger import segments
from stop_guessing.ledger.chain import ChainKey, verify
from stop_guessing.ledger.sink import load, record, record_many
from stop_guessing.recorder.guard import (
    build_manifest,
    check_ledger_dir,
    check_manifest,
    check_not_path_resolved,
    check_registration,
    isolation_tier,
    resolve_self,
)
from stop_guessing.taint.labels import is_sensitivity
from stop_guessing.taint.state import ArtifactRef, SessionCustodyState
from stop_guessing.verify.sufficiency import assess_record

KEY = ChainKey("cov", b"coverage-test-key-32-bytes-long!")
OTHER = ChainKey("oth", b"a-different-key-32-bytes-long!!!")


# ── the seal MAC (#16), newest security code ─────────────────────────────────


def _sealed(tmp_path, n=5, key=KEY):
    p = tmp_path / "seg.jsonl"
    for i in range(n):
        record(p, {"op": "artifact.read", "at": "t", "detail": str(i)}, key)
    # rotate=False: these tests exercise seal SERIALISATION over a fixed file. #63 made sealing
    # also archive the segment and move its sidecar with it, which is correct — and would leave
    # load_seal() looking at a live path whose sidecar has legitimately moved away.
    return p, segments.seal(p, at="t", key=key, index=0, rotate=False)


def test_seal_carries_a_mac_and_a_keyid(tmp_path):
    _, s = _sealed(tmp_path)
    assert s.mac and len(s.mac) == 64
    assert s.keyid == KEY.keyid


def test_seal_mac_verifies_under_the_right_key(tmp_path):
    _, s = _sealed(tmp_path)
    ok, why = s.verify_mac(KEY)
    assert ok, why


def test_seal_mac_fails_under_the_wrong_key(tmp_path):
    _, s = _sealed(tmp_path)
    ok, why = s.verify_mac(OTHER)
    assert not ok and "does not verify" in why


def test_seal_mac_absent_is_a_finding_not_a_pass(tmp_path):
    """An unsigned seal must not read as an authentic one."""
    p = tmp_path / "seg.jsonl"
    for i in range(3):
        record(p, {"op": "artifact.read", "at": "t", "detail": str(i)}, None)
    s = segments.seal(p, at="t", key=None, index=0)
    ok, why = s.verify_mac(None)
    assert not ok and "no MAC" in why


def test_seal_mac_without_a_key_is_unverified_not_verified(tmp_path):
    _, s = _sealed(tmp_path)
    ok, why = s.verify_mac(None)
    assert not ok and "unverified" in why


def test_editing_any_sealed_field_breaks_the_mac(tmp_path):
    _, s = _sealed(tmp_path)
    for field, value in (("records", 99), ("head_hash", "0" * 64), ("last_seq", 42),
                         ("prev_seal_digest", "f" * 64), ("file_digest", "a" * 64)):
        tampered = segments.Seal(**{**s.to_dict(), field: value})
        ok, _ = tampered.verify_mac(KEY)
        assert not ok, f"editing {field} did not break the MAC"


def test_seal_digest_covers_the_mac(tmp_path):
    """Otherwise a rewritten seal could keep the same link for the following segment."""
    _, s = _sealed(tmp_path)
    without = segments.Seal(**{**s.to_dict(), "mac": None})
    assert s.digest() != without.digest()


def test_segment_name_is_zero_padded():
    assert segments.segment_name(0) == "seg-000000"
    assert segments.segment_name(42) == "seg-000042"


def test_load_seal_returns_none_when_absent(tmp_path):
    assert segments.load_seal(tmp_path / "nothing.jsonl") is None


def test_load_seal_roundtrips(tmp_path):
    p, s = _sealed(tmp_path)
    assert segments.load_seal(p).to_dict() == s.to_dict()


def test_verify_all_reports_the_chain_verdict(tmp_path):
    p, _ = _sealed(tmp_path)
    out = segments.verify_all(load(p, KEY).entries, KEY)
    assert out["intact"] and out["verified_keyed"]


# ── record_many ──────────────────────────────────────────────────────────────


def test_record_many_writes_a_contiguous_chain(tmp_path):
    p = tmp_path / "l.jsonl"
    written = record_many(p, [{"op": "tool.request", "at": "t", "detail": str(i)}
                              for i in range(20)], KEY)
    assert [w["seq"] for w in written] == list(range(20))
    assert verify(load(p, KEY).entries, KEY).intact


def test_record_many_refuses_a_downgrade_mid_batch(tmp_path):
    from stop_guessing.ledger.sink import LedgerError

    p = tmp_path / "l.jsonl"
    record(p, {"op": "tool.request", "at": "t"}, KEY)
    with pytest.raises(LedgerError, match="without its chain key"):
        record_many(p, [{"op": "tool.request", "at": "t"}], None)


# ── guard sub-checks ─────────────────────────────────────────────────────────


def test_resolve_self_resolves_symlinks(tmp_path):
    real = tmp_path / "real"
    real.write_text("#!/bin/sh\n")
    link = tmp_path / "link"
    link.symlink_to(real)
    assert resolve_self(str(link)) == real.resolve()


def test_check_not_path_resolved_flags_a_shadow(tmp_path, monkeypatch):
    """The Berkeley RDI fake-curl attack, as a unit."""
    shadow_dir = tmp_path / "evil"
    shadow_dir.mkdir()
    shadow = shadow_dir / "stop-guessing"
    shadow.write_text("#!/bin/sh\necho PASS\n")
    shadow.chmod(0o755)
    real = tmp_path / "stop-guessing"
    real.write_text("#!/bin/sh\n")
    monkeypatch.setenv("PATH", f"{shadow_dir}:{os.environ.get('PATH', '')}")
    finding = check_not_path_resolved("stop-guessing", real)
    assert finding and "earlier on PATH" in finding


def test_check_not_path_resolved_is_silent_when_it_matches(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    exe = d / "stop-guessing"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(d))
    assert check_not_path_resolved("stop-guessing", exe) is None


def test_check_manifest_names_changed_and_missing(tmp_path):
    a = tmp_path / "a.sh"
    a.write_text("one\n")
    b = tmp_path / "b.sh"
    b.write_text("two\n")
    m = build_manifest(a, {"a.sh": a, "b.sh": b})
    assert check_manifest(m, tmp_path) == []
    a.write_text("edited\n")
    b.unlink()
    findings = check_manifest(m, tmp_path)
    assert any("digest changed" in f for f in findings)
    assert any("is missing" in f for f in findings)


def test_check_ledger_dir_flags_world_writable(tmp_path):
    d = tmp_path / "ledger"
    d.mkdir()
    d.chmod(0o777)
    assert any("world-writable" in f for f in check_ledger_dir(d))
    d.chmod(0o700)
    assert check_ledger_dir(d) == []


def test_check_ledger_dir_is_silent_when_absent(tmp_path):
    assert check_ledger_dir(tmp_path / "nope") == []


def test_check_registration_flags_a_literal_tilde():
    settings = {"hooks": {"PreToolUse": [{"hooks": [
        {"command": "bash ~/.claude/hooks/coc_gate.sh"}]}]}}
    findings = check_registration(settings, "bash /abs/coc_gate.sh")
    assert any("literal ~" in f for f in findings)


def test_check_registration_flags_an_absent_registration():
    findings = check_registration({"hooks": {"PreToolUse": []}}, "bash /abs/coc_gate.sh")
    assert any("no STOP-GUESSING" in f for f in findings)


def test_check_registration_accepts_the_pinned_command():
    pinned = "bash /abs/coc_gate.sh"
    settings = {"hooks": {"PreToolUse": [{"hooks": [{"command": pinned}]}]}}
    assert check_registration(settings, pinned) == []


@pytest.mark.parametrize(("daemon", "uid", "remote", "want"), [
    (False, False, False, 0), (True, False, False, 1),
    (True, True, False, 2), (True, True, True, 3), (False, False, True, 3),
])
def test_isolation_tier_is_reported_honestly(daemon, uid, remote, want):
    assert isolation_tier(daemon_running=daemon, separate_uid=uid, remote=remote) == want


# ── identity ─────────────────────────────────────────────────────────────────


def test_canonical_path_collapses_equivalent_spellings(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text("x")
    weird = tmp_path / "sub" / ".." / "a.csv"
    (tmp_path / "sub").mkdir()
    assert canonical_path(weird) == canonical_path(f)


def test_artifact_id_is_stable_and_path_equivalent(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text("x")
    (tmp_path / "sub").mkdir()
    assert artifact_id(f) == artifact_id(tmp_path / "sub" / ".." / "a.csv")
    assert artifact_id(f) == artifact_id(f)


def test_editing_content_does_not_change_identity(tmp_path):
    """Otherwise a taint could be shed by touching the file."""
    f = tmp_path / "a.csv"
    f.write_text("one")
    before = artifact_id(f)
    f.write_text("two, completely different")
    assert artifact_id(f) == before


def test_identify_records_existence_and_digest(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text("hello")
    i = identify(f)
    assert i.exists and i.content_digest and i.canonical_path == str(f.resolve())
    absent = identify(tmp_path / "nope.csv")
    assert not absent.exists and absent.content_digest is None
    assert absent.artifact_id


def test_identify_can_skip_the_content_digest(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text("hello")
    assert identify(f, digest_content=False).content_digest is None


def test_hardlinks_are_one_artifact(tmp_path):
    a = tmp_path / "a.csv"
    a.write_text("x")
    b = tmp_path / "b.csv"
    try:
        os.link(a, b)
    except OSError:
        pytest.skip("hardlinks unavailable")
    # Different names, same inode: the fs identity folds them, but the path still participates,
    # so a recycled inode cannot inherit another artifact's history.
    assert artifact_id(a) != artifact_id(b)
    assert identify(a).fs_identity == identify(b).fs_identity


# ── odds and ends with real semantics ────────────────────────────────────────


def test_is_sensitivity_separates_levels_from_flags():
    assert is_sensitivity("restricted")
    assert not is_sensitivity("pii")


def test_restricted_touched_counts_only_restricted():
    s = SessionCustodyState("s")
    s.touch(ArtifactRef("a1", "/x", None, frozenset({"restricted"})))
    s.touch(ArtifactRef("a2", "/y", None, frozenset({"confidential", "pii"})))
    assert s.restricted_touched == 1
    assert s.depth == 2


def test_ruleset_digest_changes_with_the_rules(tmp_path):
    a = tmp_path / "r1.yaml"
    a.write_text("version: 1\nrules:\n  - {id: x, pattern: 'a', labels: [internal]}\n")
    b = tmp_path / "r2.yaml"
    b.write_text("version: 1\nrules:\n  - {id: x, pattern: 'b', labels: [internal]}\n")
    assert ruleset_digest(str(a)) != ruleset_digest(str(b))


def test_load_rules_returns_rules_egress_and_a_digest():
    rules, egress, digest = load_rules()
    assert rules and egress and len(digest) == 64


def test_assess_record_reports_per_regime_gaps():
    res = assess_record({"actor": {"agent_id": "x"}})
    assert not res["actor"].complete
    assert "actor.operator" in res["actor"].missing
    assert res["actor"].total == 3


def test_guard_report_serialises():
    from stop_guessing.recorder.guard import GuardReport

    r = GuardReport()
    r.note("checked something")
    r.fail("found something")
    d = r.to_dict()
    assert d["ok"] is False and d["findings"] and d["checked"]


def test_ledger_dir_mode_is_actually_restrictive(tmp_path):
    """The written ledger must not be group- or world-readable."""
    p = tmp_path / "l.jsonl"
    record(p, {"op": "tool.request", "at": "t"}, KEY)
    assert not (p.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH))


def test_loaded_log_exposes_the_verdict(tmp_path):
    p = tmp_path / "l.jsonl"
    record(p, {"op": "tool.request", "at": "t"}, KEY)
    loaded = load(p, KEY)
    assert loaded.chain.intact and not loaded.truncated and len(loaded.entries) == 1
    assert json.loads(json.dumps(loaded.chain.to_dict()))["intact"] is True
