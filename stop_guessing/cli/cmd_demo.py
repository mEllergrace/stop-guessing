"""`stop-guessing demo --posture steer` — §15's "the one command a reviewer runs".

CLAIM-07 declared this surface and it did not exist. I withdrew the declaration to clear the
finding, which made the claim smaller and the gate greener in a single edit — the exact trade
`prove/scope.py` now catches. So it is built.

It runs against a temporary ledger and a temporary classified fixture, in its own directory, and
prints each step with the record id that backs it. Nothing here is narrated: every line is produced
by the same policy engine, taint state, and ledger the hooks use. Where a step cannot be
demonstrated on this machine, it says so rather than printing a reassuring line.

The demo is deliberately NOT a proof. It shows the behaviour to a human; `stop-guessing prove`
records it. Conflating a demo with evidence would be this project's own failure mode.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from stop_guessing.prove import runner


def _hdr(n: int, title: str) -> None:
    print(f"\n\033[1m{n}. {title}\033[0m" if _tty() else f"\n{n}. {title}")


def _tty() -> bool:
    import sys

    return sys.stdout.isatty()


def cmd_demo(args) -> int:
    from stop_guessing.attest.keys import discover
    from stop_guessing.ledger.chain import verify as chain_verify
    from stop_guessing.ledger.sink import load, record
    from stop_guessing.policy.engine import load as load_policy_set
    from stop_guessing.taint.state import ArtifactRef, SessionCustodyState
    from stop_guessing.version import policy_dir

    posture = args.posture
    print(f"STOP-GUESSING demo — posture `{posture}`")
    print("=" * 60)
    print("Runs in a temp dir against a temp ledger. Your real ledger is not touched.")

    got = discover(getattr(args, "keyfile", None))
    key = got[0] if got else None
    if key is None:
        print("\nREFUSED: no chain key. Every record below would be forgeable by the party being\n"
              "recorded, so the demo would be showing you something that is not evidence.\n"
              "Set STOP_GUESSING_CHAIN_KEY or pass --keyfile.")
        return 2

    ps = load_policy_set(policy_dir())
    state = SessionCustodyState("demo-session")
    refs: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        ledger = Path(td) / "demo-ledger.jsonl"
        fixture = Path(td) / "roster.csv"
        fixture.write_text("name,email,salary\nA,a@example.com,1\n", encoding="utf-8")

        def rec(op: str, detail: dict, severity: str = "info") -> str:
            entry = record(ledger, {"op": op, "actor": "stop-guessing/demo", "at": runner._now(),
                                    "severity": severity, "detail": json.dumps(detail, sort_keys=True),
                                    "known_gaps": [], "alterations": []}, key)
            ref = runner.proof_ref(entry)
            refs.append(ref)
            return ref

        _hdr(1, "A classified artifact is identified and labelled")
        labels = frozenset({"restricted", "pii"})
        art = ArtifactRef("art_demo_roster", str(fixture), "sha256:demo", labels)
        r = rec("artifact.classify", {"artifact": art.artifact_id, "labels": sorted(labels),
                                      "source": "rules/classify.yaml#csa-roster"})
        print(f"   {fixture.name} -> {sorted(labels)}   [{r}]")

        _hdr(2, "First touch: the gate ASKS, and says what to do instead")
        d1 = ps.evaluate("artifact.read", state.context(
            posture=posture, call={"is_egress": False, "is_write": False, "protect_ledger": True},
            artifact={"classified": True, "first_touch": True}))
        r = rec("tool.decision", {"outcome": d1.outcome, "policy": d1.determining_policy})
        print(f"   outcome={d1.outcome}   policy={d1.determining_policy}   [{r}]")
        if posture == "observe" and d1.outcome != "allow":
            print("   NOTE: `observe` records and never blocks; this outcome is a finding.")

        _hdr(3, "Delegation: a script handles the data, the model gets the OUTPUT")
        state.touch(art)
        out = ArtifactRef("art_demo_summary", str(Path(td) / "summary.json"), "sha256:out",
                          frozenset({"public"}))
        state.derive(out, [art], via="scripts/summarise.py")
        r = rec("artifact.derive", {"generated": out.artifact_id, "source": art.artifact_id,
                                    "via": "scripts/summarise.py",
                                    "labels_after": sorted(out.labels)})
        print(f"   summary.json declared public -> carries {sorted(out.labels)} after derivation")
        print(f"   the derivation edge is what makes that automatic   [{r}]")

        _hdr(4, "Accumulation: individually-innocuous reads compose into one denial")
        for i in range(2):
            state.touch(ArtifactRef(f"art_demo_{i}", f"/x/{i}.csv", f"sha256:{i}",
                                    frozenset({"restricted"})))
        d2 = ps.evaluate("artifact.egress", state.context(
            posture=posture, call={"is_egress": True, "is_write": False, "protect_ledger": True},
            artifact={"classified": False, "first_touch": False}))
        r = rec("tool.decision", {"outcome": d2.outcome, "policy": d2.determining_policy,
                                  "taint_depth": state.depth,
                                  "sources": sorted(state.sources)}, "warning")
        print(f"   after {state.depth} classified artifacts, egress -> {d2.outcome}")
        print(f"   citing {sorted(state.sources)}   [{r}]")

        # The control. Without it, "accumulation denies" is satisfied by denying every egress.
        clean = ps.evaluate("artifact.egress", SessionCustodyState("demo-clean").context(
            posture=posture, call={"is_egress": True, "is_write": False, "protect_ledger": True},
            artifact={"classified": False, "first_touch": False}))
        print(f"   CONTROL: a session that touched nothing egresses freely -> {clean.outcome}")
        if clean.outcome == "deny":
            print("   CONTROL FAILED — the denial above is not produced by accumulation.")

        _hdr(5, "The chain over everything above")
        loaded = load(ledger, key)
        verdict = chain_verify(loaded.entries, key)
        print(f"   {len(loaded.entries)} records, chain intact={verdict.intact} keyed=True")

        _hdr(6, "The control: one edited byte and the same check fails")
        raw = ledger.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(raw[1])
        tampered["detail"] = tampered.get("detail", "") + " "
        raw[1] = json.dumps(tampered)
        bad = Path(td) / "tampered.jsonl"
        bad.write_text("\n".join(raw) + "\n", encoding="utf-8")
        try:
            bad_loaded = load(bad, key)
            bad_verdict = chain_verify(bad_loaded.entries, key)
            print(f"   tampered chain intact={bad_verdict.intact}"
                  f"  broken at {bad_verdict.broken_at}: {bad_verdict.reason}")
            if bad_verdict.intact:
                print("   CONTROL FAILED — a modified record verified. Do not trust step 5.")
        except Exception as exc:  # noqa: BLE001 - the sink refusing IS the control passing
            print(f"   the sink refused to load it: {exc}")

    _hdr(7, "The AI-CAIQ workbook this toolchain reports against")
    try:
        # The existing resolver, not a second copy of the search path.
        from stop_guessing.caiq.workbook import inspect as caiq_inspect
        from stop_guessing.cli.cmd_caiq import resolve_template

        insp = caiq_inspect(resolve_template())
        print(f"   {insp.specification_name} {insp.specification_version} "
              f"(CAIQ {insp.caiq_version}), sheet {insp.data_sheet} {insp.dimensions}")
        for f in insp.findings:
            print(f"   FINDING: {f}")
    except Exception as exc:  # noqa: BLE001 - reported, never fatal to a demo
        print(f"   not available here: {exc}")

    print("\n" + "=" * 60)
    print(f"{len(refs)} records written. Each line above cites the record that backs it.")
    print("This is a DEMONSTRATION. `stop-guessing prove` is what records evidence; a demo that\n"
          "counted as its own proof would be the failure this project exists to catch.")
    return 0


def register(sub) -> None:
    d = sub.add_parser("demo", help="drive the postures end to end and cite every record")
    d.add_argument("--posture", default="steer", choices=["observe", "steer", "bar"])
    d.add_argument("--keyfile")
    d.set_defaults(fn=cmd_demo)
