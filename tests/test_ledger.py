"""M1: the keyed, tamper-evident, append-only ledger.

Every property in the M1 acceptance bar is asserted here, including the one the whole design
turns on: `test_keyed_chain_defeats_truncate_and_recompute` against
`test_unkeyed_chain_is_forgeable_which_is_why_we_key_it`. The second test is not a bug report —
it is the control that gives the first one meaning.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from stop_guessing.attest.keys import KeyUnavailable, from_env, from_keyfile, generate
from stop_guessing.ledger import segments
from stop_guessing.ledger.alerts import alerts_from, classify
from stop_guessing.ledger.chain import (
    GENESIS,
    ChainKey,
    append,
    canonical_material,
    hash_entry,
    head,
    verify,
)
from stop_guessing.ledger.reconcile import (
    Dispatch,
    Reported,
    issue_nonce,
    nonce_mode,
    reconcile,
)
from stop_guessing.ledger.sink import LedgerError, load, record

KEY = ChainKey("test-key", b"a-test-chain-key-32-bytes-long!!")
OTHER = ChainKey("other-key", b"a-different-key-32-bytes-long!!!")


def _event(i: int, **kw) -> dict:
    return {"op": "artifact.read", "actor": "agent/main", "detail": f"record {i}",
            "severity": "info", "at": f"2026-08-03T10:00:{i % 60:02d}.000Z", **kw}


def _build(n: int, key: ChainKey | None = KEY) -> list[dict]:
    log: list[dict] = []
    for i in range(n):
        log = append(log, _event(i), key)
    return log


def _write(path, log):
    path.write_text(
        "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in log),
        encoding="utf-8",
    )


# ── chain basics ─────────────────────────────────────────────────────────────


def test_empty_chain_is_intact():
    assert verify([], KEY).intact


def test_genesis_covers_the_first_entry():
    log = _build(1)
    assert log[0]["prev_hash"] == GENESIS
    assert verify(log, KEY).intact


def test_two_hundred_records_verify():
    v = verify(_build(200), KEY)
    assert v.intact and v.verified_keyed and v.checked == 200


def test_caller_cannot_choose_its_own_seq_or_predecessor():
    """A record that could pick its own sequence number could insert itself anywhere."""
    for field in ("seq", "prev_hash", "hash", "hash_alg", "keyid"):
        with pytest.raises(ValueError, match="may not set chain fields"):
            append([], {**_event(0), field: "x"}, KEY)


def test_every_field_participates_in_the_hash():
    """Structural coverage: a field added later is covered the moment it exists."""
    base = {"op": "x", "at": "t", "seq": 0, "prev_hash": GENESIS, "hash_alg": "hmac-sha256",
            "keyid": KEY.keyid}
    h1 = hash_entry(base, KEY)
    h2 = hash_entry({**base, "a_new_field_nobody_updated_the_hasher_for": 1}, KEY)
    assert h1 != h2


def test_canonical_material_is_order_independent():
    a = {"b": 2, "a": 1, "hash": "ignored"}
    b = {"a": 1, "b": 2, "hash": "different"}
    assert canonical_material(a) == canonical_material(b)


def test_head_is_the_link_a_successor_chains_to():
    assert head([]) == GENESIS
    log = _build(3)
    assert head(log) == log[-1]["hash"]


# ── tamper detection ─────────────────────────────────────────────────────────


def test_edit_in_place_is_named_by_index_and_reason():
    log = _build(200)
    log[57] = {**log[57], "detail": "TAMPERED"}
    v = verify(log, KEY)
    assert not v.intact
    assert v.broken_at == 57
    assert "edited in place" in v.reason


def test_removing_an_entry_breaks_the_link():
    log = _build(20)
    del log[10]
    v = verify(log, KEY)
    assert not v.intact
    assert v.broken_at == 10


def test_reordering_is_caught():
    log = _build(10)
    log[3], log[4] = log[4], log[3]
    assert not verify(log, KEY).intact


def test_wrong_key_does_not_verify():
    v = verify(_build(10, KEY), OTHER)
    assert not v.intact
    assert v.broken_at == 0


def test_splicing_an_unkeyed_entry_into_a_keyed_ledger_is_caught():
    log = _build(5, KEY)
    forged = {"op": "x", "actor": "a", "detail": "spliced", "at": "t", "seq": 5,
              "prev_hash": log[-1]["hash"], "hash_alg": "sha256", "keyid": None}
    forged["hash"] = hashlib.sha256(canonical_material(forged)).hexdigest()
    v = verify([*log, forged], KEY)
    assert not v.intact
    assert "spliced" in v.reason


def test_missing_chain_field_is_caught():
    log = _build(3)
    del log[1]["hash_alg"]
    v = verify(log, KEY)
    assert not v.intact and v.broken_at == 1


# ── THE property: keyed vs unkeyed under a rewrite ───────────────────────────


def _forge_tail(entries: list[dict], keymat: bytes | None, upto: int, alg: str) -> list[dict]:
    """Recompute a complete, internally consistent tail — what an attacker actually does."""
    out = list(entries)
    for i in range(len(entries), upto):
        base = {"op": "artifact.read", "actor": "agent/main", "detail": f"FABRICATED {i}",
                "severity": "info", "at": "2026-08-03T10:00:00.000Z", "seq": i,
                "prev_hash": out[-1]["hash"], "hash_alg": alg,
                "keyid": entries[0].get("keyid")}
        mat = canonical_material(base)
        base["hash"] = (hmac.new(keymat, mat, hashlib.sha256).hexdigest() if keymat
                        else hashlib.sha256(mat).hexdigest())
        out.append(base)
    return out


def test_unkeyed_chain_is_forgeable_which_is_why_we_key_it():
    """The control. rockin-robin's plain-SHA-256 chain accepts a fabricated history as intact.

    This is not a defect in rockin-robin — its threat model is an editor, not a rewriter. Here
    the recorded party has filesystem access, so it is the wrong primitive.
    """
    log = _build(150, key=None)
    forged = _forge_tail(log[:100], None, 150, "sha256")
    assert verify(forged, None).intact, "if this ever fails, the control has stopped controlling"


def test_keyed_chain_defeats_truncate_and_recompute():
    """The property the design turns on: forgery becomes unproducible, not merely detectable."""
    log = _build(150, KEY)
    # (a) attacker has no key -> plain sha256
    a = _forge_tail(log[:100], None, 150, "hmac-sha256")
    va = verify(a, KEY)
    assert not va.intact and va.broken_at == 100
    # (b) attacker substitutes a wrong key
    b = _forge_tail(log[:100], b"wrong-key-guess", 150, "hmac-sha256")
    vb = verify(b, KEY)
    assert not vb.intact and vb.broken_at == 100


def test_control_forging_with_the_real_key_succeeds():
    """Proves the key is the only thing stopping the forgery — not an unrelated accident."""
    log = _build(150, KEY)
    c = _forge_tail(log[:100], KEY.material, 150, "hmac-sha256")
    assert verify(c, KEY).intact


def test_verify_without_the_key_reports_partial_not_pass():
    """`--public` must never imply more than it checked."""
    v = verify(_build(10, KEY), None)
    assert v.intact, "link structure is still checkable"
    assert not v.verified_keyed, "but it must not claim keyed verification"


# ── the sink ─────────────────────────────────────────────────────────────────


def test_record_appends_and_verifies(tmp_path):
    p = tmp_path / "l.jsonl"
    for i in range(10):
        record(p, _event(i), KEY)
    loaded = load(p, KEY)
    assert len(loaded.entries) == 10
    assert loaded.chain.intact and loaded.chain.verified_keyed


def test_absent_ledger_is_not_an_error(tmp_path):
    loaded = load(tmp_path / "nope.jsonl", KEY)
    assert loaded.entries == [] and loaded.chain.intact and not loaded.truncated


def test_refuses_to_append_onto_a_broken_chain(tmp_path):
    p = tmp_path / "l.jsonl"
    log = _build(10)
    log[4] = {**log[4], "detail": "TAMPERED"}
    _write(p, log)
    with pytest.raises(LedgerError, match="bury the break"):
        record(p, _event(99), KEY)


def test_refuses_to_append_onto_a_torn_final_line(tmp_path):
    p = tmp_path / "l.jsonl"
    for i in range(5):
        record(p, _event(i), KEY)
    raw = p.read_text()
    p.write_text(raw[:-40])
    assert load(p, KEY).truncated
    with pytest.raises(LedgerError, match="partial"):
        record(p, _event(99), KEY)


def test_intact_prefix_survives_a_tear(tmp_path):
    """Everything before the tear is still evidence."""
    p = tmp_path / "l.jsonl"
    for i in range(5):
        record(p, _event(i), KEY)
    p.write_text(p.read_text()[:-40])
    loaded = load(p, KEY)
    assert loaded.truncated
    assert len(loaded.entries) == 4
    assert loaded.chain.intact


def test_ledger_file_is_owner_only(tmp_path):
    p = tmp_path / "l.jsonl"
    record(p, _event(0), KEY)
    assert p.stat().st_mode & 0o077 == 0


# ── segments ─────────────────────────────────────────────────────────────────


def test_seal_then_chain_the_next_segment(tmp_path):
    s0, s1 = tmp_path / "seg0.jsonl", tmp_path / "seg1.jsonl"
    for i in range(30):
        record(s0, _event(i), KEY)
    seal0 = segments.seal(s0, at="2026-08-03T11:00:00Z", key=KEY, index=0, rotate=False)
    assert seal0.records == 30
    for i in range(10):
        record(s1, _event(i), KEY)
    seal1 = segments.seal(s1, at="2026-08-03T11:01:00Z", key=KEY,
                          prev_seal_digest=seal0.digest(), index=1, rotate=False)
    assert seal1.prev_seal_digest == seal0.digest()
    result = segments.verify_series([s0, s1], KEY)
    assert result["ok"], result["findings"]
    assert result["records"] == 40


def test_modifying_a_sealed_segment_is_caught(tmp_path):
    p = tmp_path / "seg.jsonl"
    for i in range(5):
        record(p, _event(i), KEY)
    segments.seal(p, at="t", key=KEY, index=0, rotate=False)
    with open(p, "a") as fh:
        fh.write('{"seq": 99}\n')
    result = segments.verify_sealed(p, KEY)
    assert not result["ok"]
    assert any("digest changed since sealing" in f for f in result["findings"])


def test_malformed_record_appended_after_sealing_is_a_finding_not_a_crash(tmp_path):
    """A verifier that crashes on hostile input is a denial-of-verification.

    The attacker would get "the tool errored" instead of "the segment was tampered with".
    """
    p = tmp_path / "seg.jsonl"
    for i in range(3):
        record(p, _event(i), KEY)
    segments.seal(p, at="t", key=KEY, index=0, rotate=False)
    with open(p, "a") as fh:
        fh.write('{"seq": 99}\n')          # no hash, no prev_hash, no hash_alg
    result = segments.verify_sealed(p, KEY)   # must not raise
    assert not result["ok"]
    assert any("malformed record was appended" in f for f in result["findings"])


def test_refuses_to_seal_a_broken_chain(tmp_path):
    p = tmp_path / "seg.jsonl"
    log = _build(5)
    log[2] = {**log[2], "detail": "TAMPERED"}
    _write(p, log)
    with pytest.raises(LedgerError, match="certify a record we know is wrong"):
        segments.seal(p, at="t", key=KEY, rotate=False)


def test_refuses_to_seal_nothing(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("")
    with pytest.raises(LedgerError, match="nothing to seal"):
        segments.seal(p, at="t", key=KEY, rotate=False)


def test_replacing_a_segment_in_a_series_is_caught(tmp_path):
    s0, s1 = tmp_path / "seg0.jsonl", tmp_path / "seg1.jsonl"
    for i in range(5):
        record(s0, _event(i), KEY)
    seal0 = segments.seal(s0, at="t", key=KEY, index=0, rotate=False)
    for i in range(5):
        record(s1, _event(i), KEY)
    segments.seal(s1, at="t", key=KEY, prev_seal_digest=seal0.digest(), index=1, rotate=False)
    # Rebuild seg0 with different content and re-seal it: seg1 no longer chains to it.
    s0.unlink()
    for i in range(5):
        record(s0, _event(i + 100), KEY)
    segments.seal(s0, at="t", key=KEY, index=0, rotate=False)
    result = segments.verify_series([s0, s1], KEY)
    assert not result["ok"]
    assert any("replaced or removed" in f for f in result["findings"])


# ── alerts ───────────────────────────────────────────────────────────────────


def test_unrecognised_op_alerts_rather_than_being_dropped():
    d = classify({"op": "something.nobody.defined"})
    assert d.alert and d.wake == "operator"
    assert "refusing to ignore" in d.reason


def test_routine_traffic_is_quiet():
    assert not classify({"op": "artifact.read"}).alert


def test_critical_severity_wakes_a_human():
    assert classify({"op": "artifact.read", "severity": "critical"}).wake == "human"


def test_chain_break_is_the_first_alert():
    log = _build(5)
    log[2] = {**log[2], "detail": "TAMPERED"}
    found = alerts_from(log, KEY)
    assert "LEDGER CHAIN BROKEN at entry 2" in found[0].reason
    assert found[0].wake == "human"


def test_unverifiable_chain_is_flagged_not_passed():
    found = alerts_from(_build(3, KEY), None)
    assert any("never as tamper-proof" in a.reason for a in found)


# ── reconciliation ───────────────────────────────────────────────────────────


def test_nonce_is_deterministic_and_keyed_mode_differs():
    assert issue_nonce("a", 1, KEY) == issue_nonce("a", 1, KEY)
    assert issue_nonce("a", 1, KEY) != issue_nonce("a", 2, KEY)
    assert issue_nonce("a", 1, KEY) != issue_nonce("a", 1, None)
    assert issue_nonce("a", 1, KEY) != issue_nonce("a", 1, OTHER)
    assert nonce_mode(KEY) == "hmac-sha256"
    assert nonce_mode(None) == "fnv1a-derived"


def test_matching_report_reconciles():
    led = [Dispatch(0, "agent/main", "run", issue_nonce("agent/main", 0, KEY))]
    rep = [Reported(0, "agent/main", "run", issue_nonce("agent/main", 0, KEY))]
    assert reconcile(led, rep).verified


def test_fabricated_execution_is_caught():
    r = reconcile([], [Reported(7, "agent/main", "run", "whatever")])
    assert not r.verified
    assert "fabricated or replayed" in r.findings[0]


def test_unreported_execution_is_caught():
    r = reconcile([Dispatch(0, "a", "run", "n")], [])
    assert not r.verified
    assert "unreported execution" in r.findings[0]


def test_attribution_mismatch_is_caught():
    n = issue_nonce("a", 0, KEY)
    r = reconcile([Dispatch(0, "a", "run", n)], [Reported(0, "b", "run", n)])
    assert any("attribution mismatch" in f for f in r.findings)


def test_missing_nonce_is_caught():
    r = reconcile([Dispatch(0, "a", "run", "n")], [Reported(0, "a", "run", None)])
    assert any("no nonce returned" in f for f in r.findings)


def test_replay_of_the_same_seq_is_caught():
    n = issue_nonce("a", 0, KEY)
    r = reconcile([Dispatch(0, "a", "run", n)],
                  [Reported(0, "a", "run", n), Reported(0, "a", "run", n)])
    assert any("replayed" in f for f in r.findings)


# ── keys ─────────────────────────────────────────────────────────────────────


def test_env_provider_is_reported_as_the_weakest_tier(monkeypatch):
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", "x" * 32)
    got = from_env()
    assert got is not None
    _, src = got
    assert src.tier == 1
    assert "readable by anything" in src.note


def test_keyfile_must_not_be_group_or_world_readable(tmp_path):
    p = tmp_path / "k"
    p.write_bytes(generate())
    p.chmod(0o644)
    with pytest.raises(KeyUnavailable, match="not a key"):
        from_keyfile(p)


def test_keyfile_with_restrictive_mode_is_accepted(tmp_path):
    p = tmp_path / "k"
    p.write_bytes(generate())
    p.chmod(0o600)
    got = from_keyfile(p)
    assert got is not None and got[1].tier == 2


def test_generated_keys_are_distinct_and_full_length():
    a, b = generate(), generate()
    assert a != b and len(a) == 32


def test_key_material_never_appears_in_a_record():
    log = _build(3, KEY)
    blob = json.dumps(log)
    assert KEY.material.decode() not in blob
    assert log[0]["keyid"] == KEY.keyid


def test_chainkey_repr_does_not_leak_material():
    assert KEY.material.decode() not in repr(KEY)


# ── segment rotation — SG-HARD-030 (#63) ─────────────────────────────────────


def _seg_ledger(tmp_path, n=3):
    p = tmp_path / "custody.jsonl"
    for i in range(n):
        record(p, {"op": "artifact.read", "actor": "t", "severity": "info",
                   "at": f"2026-08-05T10:00:0{i}.000Z",
                   "known_gaps": [], "alterations": []}, KEY)
    return p


def test_sealing_archives_the_segment_and_opens_a_new_one(tmp_path):
    """seal() used to write a sidecar and leave the file appendable — a statement about a
    moment that had already passed."""
    p = _seg_ledger(tmp_path)
    s = segments.seal(p, at="2026-08-05T11:00:00.000Z", key=KEY, index=0)

    archive = tmp_path / f"custody.{s.segment}.jsonl"
    assert archive.is_file(), "the sealed bytes were not archived"
    assert (tmp_path / f"custody.{s.segment}.jsonl{segments.SEAL_SUFFIX}").is_file(), \
        "the sidecar did not move with its segment"
    assert p.is_file(), "the live path must still exist"


def test_the_archived_segment_still_verifies_after_rotation(tmp_path):
    p = _seg_ledger(tmp_path)
    s = segments.seal(p, at="2026-08-05T11:00:00.000Z", key=KEY, index=0)
    archived = load(tmp_path / f"custody.{s.segment}.jsonl", KEY)
    assert archived.chain.intact and len(archived.entries) == 3


def test_appends_after_sealing_go_to_the_new_segment(tmp_path):
    p = _seg_ledger(tmp_path)
    segments.seal(p, at="2026-08-05T11:00:00.000Z", key=KEY, index=0)
    record(p, {"op": "artifact.read", "actor": "t", "severity": "info",
               "at": "2026-08-05T11:01:00.000Z", "known_gaps": [], "alterations": []}, KEY)
    live = load(p, KEY)
    assert live.chain.intact
    assert len(live.entries) == 2, "genesis seal record plus the new append"


def test_the_new_segment_names_the_seal_it_follows(tmp_path):
    """Otherwise a missing segment in a series is invisible."""
    import json as _json

    p = _seg_ledger(tmp_path)
    s = segments.seal(p, at="2026-08-05T11:00:00.000Z", key=KEY, index=0)
    first = load(p, KEY).entries[0]
    assert first["op"] == "ledger.seal"
    detail = _json.loads(first["detail"])
    assert detail["follows_segment"] == s.segment
    assert detail["follows_seal_digest"] == s.digest()


def test_rotation_can_be_declined_for_callers_that_only_want_the_seal(tmp_path):
    """The option stays open: seal mathematics without closing the file is still reachable."""
    p = _seg_ledger(tmp_path)
    segments.seal(p, at="2026-08-05T11:00:00.000Z", key=KEY, index=0, rotate=False)
    assert not list(tmp_path.glob("custody.seg-*.jsonl")), "nothing should have been archived"
    assert len(load(p, KEY).entries) == 3
