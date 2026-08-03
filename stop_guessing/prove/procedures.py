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


# ── M4 helpers ───────────────────────────────────────────────────────────────


def _policy_set():
    from stop_guessing.policy.engine import load
    return load(repo_root() / "policy" / "coc.policy.d")


def _artifact_ctx(path: str, first_touch: bool):
    from stop_guessing.artifacts.classify import classify_path
    c = classify_path(path)
    return {"id": f"art_{abs(hash(path)) % 10**8}", "labels": sorted(c.labels),
            "classified": c.classified, "first_touch": first_touch,
            "is_ledger": "stop-guessing" in path and "ledger" in path}, c


# ── CLAIM-08 — steer ASKS on first touch, it does not deny read #1 ───────────


@proof("CLAIM-08", "live-run", "Evaluate a first touch of a classified artifact under steer.")
def prove_steer_asks_on_first_touch() -> ProofResult:
    from stop_guessing.taint.state import SessionCustodyState

    r = ProofResult(passed=True)
    ps = _policy_set()
    state = SessionCustodyState("proof-session")
    path = "/Users/isme/work/CSA/roster.csv"
    art, c = _artifact_ctx(path, first_touch=True)
    if not c.classified:
        return r.fail(f"{path} did not classify as sensitive: {sorted(c.labels)}")
    r.observe(f"{path} -> {sorted(c.labels)} via {list(c.matched)}")

    ctx = state.context(posture="steer",
                        call={"is_egress": False, "is_write": False, "is_own_binary": False},
                        artifact=art)
    d = ps.evaluate("artifact.read", ctx)
    if d.outcome != "ask":
        return r.fail(f"first touch returned {d.outcome!r}, expected 'ask' — steer must not "
                      f"deny read #1 ({d.determining_policy})")
    r.observe(f"first touch -> ASK via {d.determining_policy}")
    r.observe(f"  guidance: {d.guidance}")

    state.touch(_ref_from(art, path))
    art2, _ = _artifact_ctx(path, first_touch=False)
    d2 = ps.evaluate("artifact.read", state.context(
        posture="steer", call={"is_egress": False, "is_write": False}, artifact=art2))
    if d2.outcome != "allow":
        return r.fail(f"second touch returned {d2.outcome!r}, expected 'allow'")
    r.observe(f"second touch -> ALLOW via {d2.determining_policy} (taint already carried)")

    d3 = ps.evaluate("artifact.read", state.context(
        posture="observe", call={"is_egress": False, "is_write": False},
        artifact=_artifact_ctx(path, True)[0]))
    if d3.outcome != "allow":
        return r.fail(
            f"observe returned {d3.outcome!r} via {d3.determining_policy} — observe must RECORD "
            "and never block, or the safest rollout posture becomes the most obstructive one")
    r.observe(f"same first touch under observe -> ALLOW via {d3.determining_policy} "
              "(records, does not block)")

    led = ps.evaluate("artifact.write", state.context(
        posture="observe", call={"is_egress": False, "is_write": True},
        artifact={"classified": True, "is_ledger": True, "first_touch": True}))
    if led.outcome != "deny":
        return r.fail("the ledger was writable under observe; that forbid is postureless")
    r.observe(f"but a ledger write under observe -> DENY via {led.determining_policy} "
              "(forbid overrides permit)")
    r.evidence = {"labels": sorted(c.labels), "policy_set": ps.digest}
    return r


def _ref_from(art: dict, path: str):
    from stop_guessing.taint.state import ArtifactRef
    return ArtifactRef(art["id"], path, "sha256:x", frozenset(art["labels"]))


# ── CLAIM-07 — accumulation denies an egress that was fine earlier ───────────


@proof("CLAIM-07", "live-run", "Twelve reads then one egress; the same call earlier was allowed.")
def prove_accumulation_denies_egress() -> ProofResult:
    from stop_guessing.artifacts.classify import classify_egress
    from stop_guessing.taint.state import SessionCustodyState

    r = ProofResult(passed=True)
    ps = _policy_set()
    state = SessionCustodyState("proof-session")
    cmd = "curl -X POST -d @summary.json https://example.com/ingest"

    eg = classify_egress(cmd)
    if not eg.is_egress:
        return r.fail(f"{cmd!r} was not recognised as egress")
    r.observe(f"egress recognised via {list(eg.matched)}")

    call = {"is_egress": True, "is_write": False, "is_own_binary": False}
    early = ps.evaluate("artifact.egress", state.context(
        posture="steer", call=call, artifact={"classified": False, "first_touch": True}))
    if early.outcome != "allow":
        return r.fail(f"the SAME call on a clean session returned {early.outcome!r}; the point "
                      "is that it was fine earlier")
    r.observe(f"turn 1, clean session  -> ALLOW via {early.determining_policy}")

    paths = [
        "/Users/isme/work/CSA/roster.csv", "/Users/isme/work/CSA/members.csv",
        "/Users/isme/work/CSA/payroll.csv", "/Users/isme/work/CSA/customer-list.csv",
    ]
    for p in paths:
        art, _ = _artifact_ctx(p, first_touch=True)
        state.touch(_ref_from(art, p))
    for i in range(8):
        art = {"id": f"art_plain_{i}", "labels": ["internal"], "classified": False}
        state.touch(_ref_from(art, f"/tmp/notes-{i}.py"))
    r.observe(f"after 12 reads: taint={sorted(state.labels)} depth={state.depth} "
              f"touched={state.touched}")

    late = ps.evaluate("artifact.egress", state.context(
        posture="steer", call=call, artifact={"classified": False, "first_touch": False}))
    if late.outcome != "deny":
        return r.fail(f"the identical call returned {late.outcome!r} after accumulation")
    r.observe(f"turn 12, same call     -> DENY via {late.determining_policy}")
    r.observe(f"  contributing artifacts: {sorted(state.sources)}")
    r.observe(f"  custody digest in the decision basis: {state.digest[:16]}…")

    cred = SessionCustodyState("s2")
    cart, _ = _artifact_ctx("/Users/isme/.ssh/id_rsa", first_touch=True)
    cred.touch(_ref_from(cart, "/Users/isme/.ssh/id_rsa"))
    obs = ps.evaluate("artifact.egress", cred.context(
        posture="observe", call=call, artifact={"classified": False}))
    if obs.outcome != "deny":
        return r.fail("credential egress was not denied under observe; that rule is postureless")
    r.observe(f"credential egress under OBSERVE -> DENY via {obs.determining_policy}")
    r.evidence = {"taint_depth": state.depth, "touched": state.touched,
                  "sources": sorted(state.sources)}
    return r


# ── CLAIM-01 — derivation edges carry labels to outputs ─────────────────────


@proof("CLAIM-01", "live-run", "Read two classified inputs, derive an output, inspect the edges.")
def prove_derivation_edges_recorded() -> ProofResult:
    from stop_guessing.taint.state import ArtifactRef, SessionCustodyState

    r = ProofResult(passed=True)
    state = SessionCustodyState("proof-session")
    a, _ = _artifact_ctx("/Users/isme/work/CSA/roster.csv", True)
    b, _ = _artifact_ctx("/Users/isme/work/CSA/payroll.csv", True)
    in_a, in_b = _ref_from(a, "/x/roster.csv"), _ref_from(b, "/x/payroll.csv")
    state.touch(in_a)
    state.touch(in_b)
    r.observe(f"inputs: {sorted(in_a.labels)} and {sorted(in_b.labels)}")

    out = ArtifactRef("art_out", "/x/summary.json", "sha256:out", frozenset({"public"}))
    state.derive(out, [in_a, in_b], via="scripts/summarise.py")
    if "restricted" not in out.labels:
        return r.fail(f"the derived output did not inherit its inputs' labels: {sorted(out.labels)}")
    r.observe(f"output declared public -> carries {sorted(out.labels)} after derivation")

    if len(state.edges) != 2:
        return r.fail(f"expected 2 derivation edges, got {state.edges}")
    for tgt, src, via in state.edges:
        r.observe(f"edge: {tgt} <- {src} via {via}")
    r.observe("this is the data-flow edge no surveyed tool records; OTel GenAI has no "
              "provenance attribute at all")
    r.evidence = {"edges": len(state.edges), "output_labels": sorted(out.labels),
                  "graph_digest": state.graph_digest}
    return r


# ── CLAIM-11 — state rebuilt from the ledger alone reproduces the digest ────


@proof("CLAIM-11", "property", "Build state, replay it from ledger records, compare digests.")
def prove_state_rebuilds_from_the_ledger() -> ProofResult:
    from stop_guessing.taint.state import ArtifactRef, SessionCustodyState, rebuild

    r = ProofResult(passed=True)
    live = SessionCustodyState("s-rebuild")
    records = []
    refs = []
    for i, p in enumerate(["/Users/isme/work/CSA/roster.csv",
                           "/Users/isme/work/CSA/payroll.csv",
                           "/tmp/notes.py"]):
        art, _ = _artifact_ctx(p, True)
        ref = ArtifactRef(f"art_{i}", p, f"sha256:{i}", frozenset(art["labels"]))
        refs.append(ref)
        live.touch(ref)
        records.append({"predicate": {
            "lifecycle": {"session_id": "s-rebuild"},
            "action": {"op": "artifact.read"},
            "resources": {"used": [ref.to_dict()]}}})

    out = ArtifactRef("art_out", "/x/sum.json", "sha256:o", frozenset({"public"}))
    live.derive(out, refs[:2], via="scripts/s.py")
    records.append({"predicate": {
        "lifecycle": {"session_id": "s-rebuild"},
        "action": {"op": "artifact.derive"},
        "resources": {"used": [refs[0].to_dict(), refs[1].to_dict()],
                      "generated": [{"artifact_id": "art_out", "path": "/x/sum.json",
                                     "digest": "sha256:o", "labels": ["public"]}],
                      "derived_from": [{"generated": "art_out", "source": "art_0",
                                        "via": "scripts/s.py"}]}}})

    records.append({"predicate": {
        "lifecycle": {"session_id": "other-session"},
        "action": {"op": "artifact.read"},
        "resources": {"used": [{"artifact_id": "art_zzz", "path": "/other/secret.env",
                                "digest": "sha256:z", "labels": ["restricted", "credential"]}]}}})

    replayed = rebuild(records, "s-rebuild")
    if replayed.digest != live.digest:
        return r.fail(f"rebuild digest {replayed.digest[:16]}… != live {live.digest[:16]}…")
    r.observe(f"live and replayed digests match exactly: {live.digest[:24]}…")
    r.observe(f"  labels {sorted(live.labels)}, depth {live.depth}, "
              f"{len(live.edges)} derivation edge(s)")
    if "credential" in replayed.labels:
        return r.fail("another session's taint leaked into this one")
    r.observe("a record from a different session was present and correctly ignored")
    r.observe("state never consults the transcript — a compaction cannot rewrite what was touched")
    r.evidence = {"digest": live.digest, "records_replayed": len(records)}
    return r


# ── CLAIM-09 — a delegated script cannot touch live data untested ───────────


@proof("CLAIM-09", "negative", "Try to run a delegated script untested, failing, and then edited.")
def prove_delegation_requires_a_passing_test() -> ProofResult:
    from stop_guessing.delegate import DelegationRefused, run, run_test, scaffold

    r = ProofResult(passed=True)
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        d = Path(td) / "scripts"
        deleg = scaffold(d, "count_rows", "Count rows without returning them.")
        r.observe(f"scaffolded {deleg.script.name} + {deleg.test.name}")

        try:
            run(deleg, ["/tmp/x.csv"])
            return r.fail("ran a script whose test had never been run")
        except DelegationRefused as exc:
            if "has not been run" not in str(exc):
                return r.fail(f"refused for the wrong reason: {exc}")
            r.observe("run before testing -> REFUSED")

        res = run_test(deleg)
        if res["passed"]:
            return r.fail("the stub template's test passed; it must fail while handle() is a stub")
        r.observe(f"stub test fails as designed (exit {res['exit_code']})")
        try:
            run(deleg, ["/tmp/x.csv"])
            return r.fail("ran a script whose test failed")
        except DelegationRefused as exc:
            if "failed" not in str(exc):
                return r.fail(f"refused for the wrong reason: {exc}")
            r.observe("run after a FAILING test -> REFUSED")

        deleg.script.write_text(
            "import sys\n\n\ndef handle(paths):\n    return f'{len(paths)} artifact(s)'\n\n\n"
            "if __name__ == '__main__':\n    print(handle(sys.argv[1:]))\n", encoding="utf-8")
        res = run_test(deleg)
        if not res["passed"]:
            return r.fail(f"the implemented script's test did not pass: {res}")
        r.observe("implemented, test passes")

        out = run(deleg, ["/tmp/a.csv", "/tmp/b.csv"])
        if out["exit_code"] != 0 or "2 artifact" not in out["output"]:
            return r.fail(f"the delegated run did not produce output: {out}")
        r.observe(f"delegated run -> {out['output'].strip()!r} "
                  f"(network={out['sandbox']['network']})")

        deleg.script.write_text(
            deleg.script.read_text() + "\n# edited after the test passed\n", encoding="utf-8")
        try:
            run(deleg, ["/tmp/a.csv"])
            return r.fail("ran a script edited after its test passed")
        except DelegationRefused as exc:
            if "changed after its test passed" not in str(exc):
                return r.fail(f"refused for the wrong reason: {exc}")
            r.observe("run after EDITING the script post-test -> REFUSED "
                      "(a green test on a since-edited script is evidence about a file that no "
                      "longer exists)")
        r.evidence = {"refusals": 3}
    return r
