"""Proof procedures for the claims whose milestones have landed.

Each exercises the real surface — a real ledger file on disk, the real vendored hooks, the real
CSA template — and returns what it observed. None of them asserts; they *report*, and the runner
records the report. A procedure that returns ``passed=False`` is a working procedure telling the
truth about a broken claim.

Claims whose milestones have not landed have no procedure. `stop-guessing claims check` reports
them as unproven, which at release time is a **failed** claim, not an unassessed one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from stop_guessing.artifacts.digest import file_digest
from stop_guessing.caiq.workbook import inspect as caiq_inspect
from stop_guessing.ledger import segments
from stop_guessing.ledger.chain import ChainKey, append, canonical_material, verify
from stop_guessing.ledger.sink import LedgerError, load, record
from stop_guessing.prove.registry import ProofResult, proof
from stop_guessing.version import repo_root

PROOF_KEY = ChainKey("proof-procedure-key", b"procedure-local-key-32-bytes!!!!")
OTHER_KEY = ChainKey("wrong-key", b"a-different-key-32-bytes-long!!!")


def _event(i: int) -> dict:
    return {"op": "artifact.read", "actor": "agent/main", "detail": f"record {i}",
            "severity": "info", "at": f"2026-08-03T10:00:{i % 60:02d}.000Z"}


def _forge(entries: list[dict], keymat: bytes | None, upto: int) -> list[dict]:
    out = list(entries)
    for i in range(len(entries), upto):
        base = {"op": "artifact.read", "actor": "agent/main", "detail": f"FABRICATED {i}",
                "severity": "info", "at": "2026-08-03T10:00:00.000Z", "seq": i,
                "prev_hash": out[-1]["hash"], "hash_alg": entries[0]["hash_alg"],
                "keyid": entries[0].get("keyid")}
        mat = canonical_material(base)
        base["hash"] = (hmac.new(keymat, mat, hashlib.sha256).hexdigest() if keymat
                        else hashlib.sha256(mat).hexdigest())
        out.append(base)
    return out


# ── CLAIM-02 — keyed chain defeats truncate-and-recompute ────────────────────


@proof("CLAIM-02", "adversarial", "Forge a chain three ways against a real ledger on disk.")
def prove_keyed_chain_defeats_forgery() -> ProofResult:
    r = ProofResult(passed=True)
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        p = Path(td) / "ledger.jsonl"
        for i in range(150):
            record(p, _event(i), PROOF_KEY)
        entries = load(p, PROOF_KEY).entries
        if not verify(entries, PROOF_KEY).intact:
            return r.fail("the honest 150-record ledger did not verify")
        r.observe(f"150 records written to a real file; chain verifies (keyed, {PROOF_KEY.keyid})")

        # (a) attacker with no key falls back to plain sha256
        va = verify(_forge(entries[:100], None, 150), PROOF_KEY)
        if va.intact or va.broken_at != 100:
            return r.fail(f"forgery with no key was not caught at 100: {va.to_dict()}")
        r.observe(f"forged with no key      -> caught at entry {va.broken_at}: {va.reason}")

        # (b) attacker substitutes a wrong key
        vb = verify(_forge(entries[:100], OTHER_KEY.material, 150), PROOF_KEY)
        if vb.intact or vb.broken_at != 100:
            return r.fail(f"forgery with a wrong key was not caught at 100: {vb.to_dict()}")
        r.observe(f"forged with wrong key   -> caught at entry {vb.broken_at}")

        # (c) control — with the real key the same forgery succeeds
        vc = verify(_forge(entries[:100], PROOF_KEY.material, 150), PROOF_KEY)
        if not vc.intact:
            return r.fail("control failed: forging WITH the real key should succeed")
        r.observe("control: forged WITH the real key -> intact, so the key is what stops (a)/(b)")

        # (d) the gap this closes — an unkeyed ledger accepts the same forgery
        u = Path(td) / "unkeyed.jsonl"
        for i in range(150):
            record(u, _event(i), None)
        ue = load(u, None).entries
        vd = verify(_forge(ue[:100], None, 150), None)
        if not vd.intact:
            return r.fail("the unkeyed control stopped controlling — re-derive this proof")
        r.observe("unkeyed ledger accepts 50 fabricated records as intact — the gap being closed")
        r.evidence = {"records": 150, "truncated_at": 100, "fabricated": 50,
                      "unkeyed_forgery_undetected": True}
    return r


# ── CLAIM-03 — refuses to append onto a broken or truncated chain ────────────


@proof("CLAIM-03", "negative", "Append onto a tampered and onto a torn ledger; both must refuse.")
def prove_sink_refuses_bad_chains() -> ProofResult:
    r = ProofResult(passed=True)
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        p = Path(td) / "tampered.jsonl"
        log: list[dict] = []
        for i in range(10):
            log = append(log, _event(i), PROOF_KEY)
        log[4] = {**log[4], "detail": "TAMPERED"}
        p.write_text("".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n"
                             for e in log), encoding="utf-8")
        try:
            record(p, _event(99), PROOF_KEY)
            return r.fail("appended onto a tampered chain — the break would have been buried")
        except LedgerError as exc:
            if "bury the break" not in str(exc):
                return r.fail(f"refused, but not for the right reason: {exc}")
            r.observe("append onto a tampered chain -> REFUSED, citing entry 4")

        q = Path(td) / "torn.jsonl"
        for i in range(5):
            record(q, _event(i), PROOF_KEY)
        q.write_text(q.read_text()[:-40])
        loaded = load(q, PROOF_KEY)
        if not loaded.truncated:
            return r.fail("a torn final line was not detected")
        if len(loaded.entries) != 4 or not loaded.chain.intact:
            return r.fail("the intact prefix before the tear was not preserved")
        r.observe("torn final line detected; the 4-record intact prefix is still evidence")
        try:
            record(q, _event(99), PROOF_KEY)
            return r.fail("appended onto a torn ledger")
        except LedgerError as exc:
            if "partial" not in str(exc):
                return r.fail(f"refused, but not for the right reason: {exc}")
            r.observe("append onto a torn ledger -> REFUSED")
        r.evidence = {"tampered_at": 4, "intact_prefix": 4}
    return r


# ── CLAIM-04 — seal and archive, never truncate ──────────────────────────────


@proof("CLAIM-04", "live-run", "Seal a segment, chain the next to it, then modify the sealed one.")
def prove_segments_seal_and_chain() -> ProofResult:
    r = ProofResult(passed=True)
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        s0, s1 = Path(td) / "seg0.jsonl", Path(td) / "seg1.jsonl"
        for i in range(30):
            record(s0, _event(i), PROOF_KEY)
        seal0 = segments.seal(s0, at="2026-08-03T11:00:00Z", key=PROOF_KEY, index=0)
        r.observe(f"sealed seg-000000: {seal0.records} records, head {seal0.head_hash[:16]}…")

        for i in range(10):
            record(s1, _event(i), PROOF_KEY)
        seal1 = segments.seal(s1, at="2026-08-03T11:01:00Z", key=PROOF_KEY,
                              prev_seal_digest=seal0.digest(), index=1)
        if seal1.prev_seal_digest != seal0.digest():
            return r.fail("segment 1 does not chain to segment 0's seal digest")
        r.observe(f"seg-000001 chains to seg-000000's seal digest {seal0.digest()[:16]}…")

        series = segments.verify_series([s0, s1], PROOF_KEY)
        if not series["ok"]:
            return r.fail(f"series verification failed: {series['findings']}")
        r.observe(f"series verifies: {series['segments']} segments, {series['records']} records")

        with open(s0, "a") as fh:
            fh.write('{"seq": 99}\n')
        after = segments.verify_sealed(s0, PROOF_KEY)
        if after["ok"]:
            return r.fail("a modified sealed segment still verified")
        r.observe(f"modifying the sealed segment -> caught: {after['findings'][0][:90]}")

        try:
            segments.seal(s0, at="t", key=PROOF_KEY, index=0)
            return r.fail("sealed a broken chain")
        except LedgerError:
            r.observe("re-sealing the broken segment -> REFUSED")
        r.evidence = {"segments": 2, "records": series["records"]}
    return r


# ── CLAIM-16 — supersession is byte-compatible ───────────────────────────────


@proof("CLAIM-16", "property", "Replay the whole corpus and diff against the recorded golden.")
def prove_compat_golden_holds() -> ProofResult:
    r = ProofResult(passed=True)
    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.main", "compat", "verify"],
        capture_output=True, cwd=str(repo_root()), timeout=900,
    )
    out = res.stdout.decode() + res.stderr.decode()
    if res.returncode != 0:
        return r.fail(f"compat verify exited {res.returncode}: {out[-400:]}")
    r.observe(out.strip().splitlines()[-1])
    golden = json.loads((repo_root() / "fixtures" / "compat-golden.json").read_text())
    blocked = sum(1 for v in golden["outcomes"].values() if v["exit_code"] == 2)
    r.observe(f"golden: {golden['_cases']} cases, {golden['_invocations']} invocations, "
              f"{blocked} blocked")
    r.evidence = {"cases": golden["_cases"], "invocations": golden["_invocations"],
                  "blocked": blocked,
                  "golden_digest": file_digest(repo_root() / "fixtures" / "compat-golden.json")}
    return r


# ── CLAIM-14 — the AI-CAIQ version gate reads A1, not the sheet name ─────────


@proof("CLAIM-14", "negative", "Inspect the real template, then a copy whose A1 declares 1.0.2.")
def prove_caiq_version_gate() -> ProofResult:
    r = ProofResult(passed=True)
    pinned = json.loads(
        (repo_root() / "docs" / "ai-caiq" / "reference" / "TEMPLATE.json").read_text()
    )
    tpl = Path("/Users/isme/Software/rockin-robin/docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx")
    if not tpl.is_file():
        return r.fail(f"the local CSA template is not present at {tpl}")

    before = file_digest(tpl)
    before_mtime = tpl.stat().st_mtime_ns
    ins = caiq_inspect(tpl)
    if ins.findings:
        return r.fail(f"the real template did not match the pinned expectation: {ins.findings}")
    if ins.digest != pinned["sha256"]:
        return r.fail("the template digest no longer matches TEMPLATE.json — COPY-ONLY VIOLATION")
    r.observe(f"real template: A1 declares {ins.specification_version}/{ins.caiq_version}, "
              f"dimensions {ins.dimensions}, no findings")

    try:
        import openpyxl
    except ImportError:
        return r.fail("openpyxl unavailable")
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        drift = Path(td) / "drift.xlsx"
        drift.write_bytes(tpl.read_bytes())
        wb = openpyxl.load_workbook(drift)
        wb["AI-CAIQv1.1.0"].cell(1, 1).value = json.dumps(
            {"specification_name": "AI Controls Matrix",
             "specification_version": "1.0.2", "caiq_version": "1.0.2"})
        wb.save(drift)
        d = caiq_inspect(drift)
        if d.ok:
            return r.fail("a drifted workbook passed the gate")
        if d.data_sheet != "AI-CAIQv1.1.0":
            return r.fail("the drift fixture did not keep the original sheet name, "
                          "so it does not demonstrate the point")
        r.observe("copy with sheet name STILL 'AI-CAIQv1.1.0' but A1 declaring 1.0.2 -> caught: "
                  + "; ".join(d.findings))

    if file_digest(tpl) != before or tpl.stat().st_mtime_ns != before_mtime:
        return r.fail("inspection modified the template — COPY-ONLY VIOLATION")
    r.observe(f"copy-only holds: template digest and mtime unchanged ({before[:16]}…)")
    r.evidence = {"template_sha256": before, "pinned_sha256": pinned["sha256"]}
    return r


# ── CLAIM-13 — fabricated execution claims are caught ────────────────────────


@proof("CLAIM-13", "adversarial", "Reconcile a dispatch ledger against fabricated agent reports.")
def prove_reconciliation_catches_fabrication() -> ProofResult:
    from stop_guessing.ledger.reconcile import Dispatch, Reported, issue_nonce, reconcile

    r = ProofResult(passed=True)
    led = [Dispatch(i, "agent/main", "run", issue_nonce("agent/main", i, PROOF_KEY))
           for i in range(3)]

    honest = [Reported(d.seq, d.actor, d.action, d.nonce) for d in led]
    if not reconcile(led, honest).verified:
        return r.fail("honest reports did not reconcile")
    r.observe("honest reports reconcile")

    cases = {
        "fabricated": ([*honest, Reported(9, "agent/main", "run", "made-up")],
                       "fabricated or replayed"),
        "replayed": ([*honest, honest[0]], "replayed"),
        "attribution": ([Reported(0, "agent/other", "run", led[0].nonce), *honest[1:]],
                        "attribution mismatch"),
        "nonce": ([Reported(0, "agent/main", "run", "wrong-nonce"), *honest[1:]],
                  "nonce mismatch"),
        "unreported": (honest[:2], "unreported execution"),
    }
    for name, (reports, expect) in cases.items():
        res = reconcile(led, reports)
        if res.verified or not any(expect in f for f in res.findings):
            return r.fail(f"{name}: expected {expect!r}, got {res.findings}")
        r.observe(f"{name:<12} -> caught: {next(f for f in res.findings if expect in f)[:80]}")
    r.evidence = {"attacks_caught": len(cases)}
    return r


# ── CLAIM-05 — a missing `alterations` key is refused; `[]` is accepted ──────


@proof("CLAIM-05", "negative", "Emit a record with alterations absent, then with it empty.")
def prove_absent_alterations_is_refused() -> ProofResult:
    from stop_guessing.ledger.entry import CustodyRecord, RecordInvalid, validate_tier_a

    r = ProofResult(passed=True)
    base = dict(
        op="artifact.read", agent_id="spiffe://local/test/agent/main",
        runtime_action_id="toolu_test", operator={"identity": "test", "uid": 501},
        session_id="s1", posture="steer", outcome="allow", channel="test",
        at="2026-08-03T10:00:00Z", recorded_at="2026-08-03T10:00:00Z", record_id="sg:test",
        input_digest="sha256:" + "0" * 64, policy_set_digest="sha256:x",
        determining_policy="10-base#allow",
    )

    ok = CustodyRecord(**base).build()
    if ok["predicate"]["alterations"] != []:
        return r.fail("an empty alterations list did not survive the build")
    r.observe("alterations: []  -> ACCEPTED (a positive assertion that nothing was altered)")

    pred = CustodyRecord(**base).predicate()
    del pred["alterations"]
    missing = validate_tier_a(pred)
    if not any("alterations" in m for m in missing):
        return r.fail("a record with alterations absent was not rejected")
    r.observe(f"alterations absent -> REJECTED: {next(m for m in missing if 'alterations' in m)}")

    pred2 = CustodyRecord(**base).predicate()
    del pred2["verification"]["known_gaps"]
    if not any("known_gaps" in m for m in validate_tier_a(pred2)):
        return r.fail("a record with known_gaps absent was not rejected")
    r.observe("verification.known_gaps absent -> REJECTED (same rule: [] asserts, absent hides)")

    try:
        CustodyRecord(**{**base, "op": "not.a.real.op"}).build()
        return r.fail("an op outside the controlled vocabulary was accepted")
    except RecordInvalid as exc:
        r.observe(f"op outside the vocabulary -> REJECTED: {exc.missing[0]}")

    try:
        CustodyRecord(**{**base, "outcome": "probably"}).build()
        return r.fail("an outcome outside the vocabulary was accepted")
    except RecordInvalid as exc:
        r.observe(f"outcome outside the vocabulary -> REJECTED: {exc.missing[0]}")

    r.evidence = {"tier_a_fields": len(validate_tier_a({}))}
    return r


# ── CLAIM-06 — sufficiency reports incomplete rather than overclaiming ──────


@proof("CLAIM-06", "negative", "Assess a deliberately gapped ledger and a fuller one.")
def prove_sufficiency_refuses_to_overclaim() -> ProofResult:
    from stop_guessing.ledger.entry import CustodyRecord
    from stop_guessing.verify.sufficiency import assess

    r = ProofResult(passed=True)

    empty = assess([])
    if empty["verdict"] != "incomplete":
        return r.fail("an empty ledger did not report incomplete")
    r.observe("empty ledger -> INCOMPLETE ('an empty ledger answers nothing')")

    thin = CustodyRecord(
        op="artifact.read", agent_id="spiffe://local/test/agent/main",
        runtime_action_id="toolu_test", operator={"identity": "t", "uid": 1},
        session_id="s1", posture="steer", outcome="allow", channel="test",
        at="t", recorded_at="t", record_id="sg:1", input_digest="sha256:x",
        policy_set_digest="sha256:y", determining_policy="p",
    ).build()
    gapped = assess([thin])
    if gapped["verdict"] != "incomplete":
        return r.fail("a Tier-A-valid but evidence-thin record was reported sufficient — "
                      "this is exactly the DEMM-Bench overclaim")
    blocked = {q: v["blocked_by"] for q, v in gapped["questions"].items() if not v["answerable"]}
    if not blocked:
        return r.fail("no question was reported as blocked")
    r.observe(f"Tier-A-valid but thin record -> INCOMPLETE, {len(blocked)}/"
              f"{gapped['questions_total']} questions unanswerable")
    for q, by in list(blocked.items())[:2]:
        r.observe(f"  '{q}' blocked by: {', '.join(by)}")

    full = CustodyRecord(
        op="artifact.read", agent_id="spiffe://local/test/agent/main",
        runtime_action_id="toolu_test", operator={"identity": "t", "uid": 1},
        session_id="s1", posture="steer", outcome="allow", channel="test",
        at="t", recorded_at="t", record_id="sg:2", input_digest="sha256:x",
        policy_set_digest="sha256:y", determining_policy="p",
        extra={
            "authority": {"capability": {"grant_id": "cap_1", "scope": ["read:project"]}},
            "decision": {"basis": {"taint_labels": [], "taint_depth": 0}},
            "resources": {"used": [{"artifact_id": "art_1", "digest": "sha256:z"}]},
            "lifecycle": {"prompt_id": "prm_1"},
        },
    ).build()
    rich = assess([full])
    if rich["verdict"] != "sufficient":
        return r.fail(f"a fully populated record was still incomplete: {rich['questions']}")
    r.observe(f"fully populated record -> SUFFICIENT, {rich['answerable']}/"
              f"{rich['questions_total']} questions answerable")
    r.observe("the gate distinguishes 'a ledger exists' from 'the ledger answers the question'")
    r.evidence = {"regimes": len(rich["regimes"]), "questions": rich["questions_total"]}
    return r
