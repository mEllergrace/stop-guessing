"""`stop-guessing prove | claims | attest` — the goal surface."""

from __future__ import annotations

import json
from pathlib import Path

from stop_guessing.attest.keys import discover, keyid_of_ledger
from stop_guessing.ledger.chain import ChainKey
from stop_guessing.prove import runner
from stop_guessing.prove.registry import all_procedures


def _key(args) -> ChainKey | None:
    # discover(), not from_env(): an installed profile keeps its key in a
    # mode-600 keyfile that install.sh writes, and looking only at the
    # environment meant that key was never found. --keyfile still wins.
    #
    # prefer_keyid: when a ledger already exists, the key it was WRITTEN under
    # beats the best-protected key available. Otherwise adding a stronger
    # provider silently re-keys an existing chain and every prior entry starts
    # failing verification — reported, misleadingly, as tampering.
    got = discover(
        getattr(args, "keyfile", None),
        prefer_keyid=keyid_of_ledger(_ledger(args)),
    )
    return got[0] if got else None


def _ledger(args) -> Path:
    return Path(args.ledger) if getattr(args, "ledger", None) else runner.DEFAULT_LEDGER


def _version_drift() -> list[str]:
    """Manifests whose declared version disagrees with VERSION. Empty means the tree is stamped.

    Every proof record pins the version, so proving against an unstamped tree produces proofs that
    the gate immediately — and correctly — invalidates as `version changed since this proof`. That
    happened twice during 0.5.x: the fix was stamped after proving, twenty-one proofs died at once,
    and the resulting wall of findings looked like a real regression while meaning only "you
    stamped last". Twenty-five minutes of proving, discarded, twice.
    """
    import sys as _sys
    from pathlib import Path as _P

    scripts = _P(__file__).resolve().parent.parent.parent / "scripts"
    if not (scripts / "stamp_version.py").is_file():
        return []              # installed from a wheel: no repo to be out of step with
    _sys.path.insert(0, str(scripts))
    try:
        from stamp_version import stamp
    except ImportError:
        return []
    # `stamp(check_only=True)` is the same comparison `stamp_version.py --check` already makes, so
    # the guard and the checker cannot disagree. Comparing `declared_versions()` directly looked
    # equivalent and was not: its README entry is the whole matched string ("**Version 0.5.1"),
    # never equal to a bare version, so a hand-rolled comparison reported permanent drift and would
    # have refused EVERY prove run. Caught by the control test, not by reading it.
    return list(stamp(check_only=True))


def cmd_prove(args) -> int:
    drift = [] if getattr(args, "allow_version_drift", False) else _version_drift()
    if drift:
        print("REFUSED: the tree is not stamped. These declare a different version from VERSION:")
        for d in drift:
            print(f"    {d}")
        print("\nEvery proof pins the version, so proving now produces proofs the gate will "
              "invalidate\nthe moment you stamp — a full run discarded for nothing. Run:")
        print("    python3 scripts/stamp_version.py")
        print("\nThen prove. `--allow-version-drift` overrides this if you know why you want it.")
        return 2

    key = _key(args)
    if key is None:
        print("REFUSED: no chain key. A proof recorded in an unkeyed ledger is forgeable by the\n"
              "         party being recorded, so it is not a proof. Set STOP_GUESSING_CHAIN_KEY\n"
              "         or pass --keyfile.")
        return 2

    procs = all_procedures()
    if args.claim:
        targets = [args.claim]
    elif args.milestone:
        doc = runner.load_claims()
        targets = [c["id"] for c in doc["claims"]
                   if c.get("milestone") == args.milestone and c["id"] in procs]
    else:
        targets = sorted(procs)

    if not targets:
        print("no registered procedures match")
        return 1

    failed = 0
    for cid in targets:
        out = runner.run_one(cid, key, _ledger(args))
        mark = "PASS" if out.passed else "FAIL"
        print(f"\n{mark}  {cid}  -> {out.ref or 'not recorded'}")
        for o in out.observations:
            print(f"      {o}")
        if out.detail:
            print(f"      {out.detail}")
        if not out.passed:
            failed += 1
    print(f"\n{len(targets) - failed}/{len(targets)} proved")
    return 1 if failed else 0


def cmd_claims_check(args) -> int:
    """The release gate.

    #38 (SG-HARD-005): the exit code is now a contract, because CI captured it and echoed it and
    therefore could not fail. "Cannot verify" and "verified, found a problem" are different states
    and must not collapse into one silent pass:

        0  verified, no findings
        1  verified, findings — unproven claims, dead evidence, a broken or truncated ledger
        2  cannot verify — no chain key, so nothing was actually checked
    """
    key = _key(args)
    result = runner.check(key, _ledger(args))
    print(f"ledger: {result['ledger']}")
    print(f"chain : intact={result['chain_intact']} keyed={result['chain_keyed']}"
          + (" TRUNCATED" if result.get("chain_truncated") else ""))
    if not result["chain_intact"]:
        print(f"        {result['chain_reason']}")
    print()
    for row in result["rows"]:
        # #35: NO-PROC is checked BEFORE PROVEN. It used to be the other way round, so a claim
        # whose procedure had been deleted printed PROVEN and the missing procedure never showed.
        if not row["has_procedure"]:
            mark = "NO-PROC "
        elif row["proven"]:
            mark = "PROVEN  "
        else:
            mark = "UNPROVEN"
        extra = ""
        if row["dead"]:
            extra = "  !! " + "; ".join(row["dead"])
        if not row["kind_matches"] and row["has_procedure"]:
            extra += "  !! procedure kind does not match the declared proof_kind"
        for f in row.get("surface_findings") or []:
            extra += f"  !! {f}"
        print(f"  {mark} {row['id']:<10} {str(row['milestone']):<4} "
              f"{row['proof_kind']:<12} {len(row['live'])} proof(s){extra}")

    unvalidated = sorted({s for r in result["rows"] for s in (r.get("unvalidated_surfaces") or [])})
    if unvalidated:
        print(f"\n{len(unvalidated)} declared surface(s) are NOT validated by this gate — only "
              f"`hook:` is decidable today. Unchecked, not passed:")
        for s in unvalidated[:8]:
            print(f"    {s}")
        if len(unvalidated) > 8:
            print(f"    … and {len(unvalidated) - 8} more")

    print(f"\n{result['proven']}/{result['total']} claims proven")
    if key is None:
        print("\nCANNOT VERIFY: no chain key, so the ledger was not authenticated and nothing "
              "above was actually checked.")
        return 2
    if not result["ok"]:
        print("A claim with no surviving proof is a FAILED claim, not an unassessed one.")
    return 0 if result["ok"] else 1


def cmd_claims_retract(args) -> int:
    """Record a reasoned reduction in what a claim asserts — ISO 27037 §5.4.1.

    Reducing a claim's scope alters the evidence subject, so it needs a written justification in
    the ledger, exactly as any other alteration does. This command exists so that the reduction is
    a deliberate act with an author and a reason, rather than a YAML edit nobody sees.

    Editing the claims file still works — it is a text file and locking it would be theatre. What
    changed is that an unjustified reduction is now a FINDING, so the silent path leads somewhere
    visible instead of nowhere.
    """
    from stop_guessing.ledger.sink import record
    from stop_guessing.prove import scope as _scope

    key = _key(args)
    if key is None:
        print("REFUSED: no chain key. A retraction recorded in an unkeyed ledger is forgeable by "
              "the party whose claim is shrinking.")
        return 2
    try:
        ev = _scope.retraction_event(args.claim, args.field, args.removed, args.reason)
    except ValueError as exc:
        print(f"REFUSED: {exc}")
        return 2
    ev.update({"actor": f"stop-guessing/{runner.__name__}", "at": runner._now()})
    entry = record(_ledger(args), ev, key)
    print(f"recorded: {args.claim} no longer asserts {args.field}: {', '.join(args.removed)}")
    print(f"  reason : {args.reason}")
    print(f"  record : {runner.proof_ref(entry)}")
    print("\nThis is an ISO 27037 alteration. It does not make the reduction invisible — it makes "
          "it accounted for.")
    return 0


def cmd_attest(args) -> int:
    result = runner.attest_self(_key(args), _ledger(args))
    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["goal_met"] else 1

    print("STOP-GUESSING — self-attestation\n" + "=" * 46)
    print(f"claims proven      : {result['proven']}/{result['total']}")
    print(f"ledger chain       : intact={result['chain_intact']} keyed={result['chain_keyed']}")
    print(f"AICM controls with evidence: {len(result['aicm_controls_evidenced'])}")
    for ctrl, claims in result["aicm_controls_evidenced"].items():
        print(f"    {ctrl:<12} {', '.join(claims)}")
    caiq = result["caiq"]
    print(f"AI-CAIQ answers    : {'present' if caiq['answers_present'] else 'ABSENT'}")
    print(f"AI-CAIQ workbooks  : {caiq['filled_workbooks'] or 'NONE'}")
    print(f"workbook bound     : {caiq.get('workbook_digest_bound')}")
    for f in caiq.get("findings") or []:
        print(f"  CAIQ FINDING     : {f}")
    # #77 (SG-HARD-044): four axes, printed separately. One boolean collapsed "the procedures ran"
    # with "the evidence is adequate" and with "someone else reproduced it", so a flattering
    # headline could sit on top of 21 recorded independence objections.
    a = result.get("assurance") or {}
    if a:
        print("\nassurance axes     : deliberately not collapsed into one verdict")
        for k in ("executed", "chain_verified", "surface_validated", "control_backed",
                  "independently_reproduced"):
            print(f"    {k:<26} {a.get(k)}")
        if a.get("unvalidated_surfaces"):
            print(f"    {'surfaces unchecked':<26} {len(a['unvalidated_surfaces'])}")

    j = result.get("judge") or {}
    if j:
        print(f"\njudge panel        : {j['claims_judged']} claims, {j['verdicts']} verdicts, "
              f"{j['deferred_disapprovals']} deferred disapproval(s)")
        for lens, n in (j.get("by_lens") or {}).items():
            print(f"    {lens:<24} {n} claim(s)")
        print(f"    {j['disclosure']}")
    print()
    if result["goal_met"]:
        print("GOAL MET.")
        return 0
    print("GOAL NOT MET. Outstanding:")
    if result["unproven"]:
        print(f"  - unproven claims: {', '.join(result['unproven'])}")
    if not result["chain_keyed"]:
        print("  - the proof ledger is not keyed-verified")
    if not caiq["filled_from_proofs"]:
        print("  - the AI-CAIQ has not been filled from those proofs (M10, and strictly last)")

    # The axes, which are what `goal_met` (== release_assured) actually requires. Without these
    # the command printed "GOAL NOT MET. Outstanding:" followed by nothing at all, because the
    # three conditions above were satisfied and the failing ones were never listed. A verdict that
    # states no reason is exactly what this toolchain exists to stop other people shipping.
    if not a.get("surface_validated"):
        live = set(a.get("surfaces_requiring_live_session") or [])
        rest = [s for s in (a.get("unvalidated_surfaces") or []) if s not in live]
        if live:
            print(f"  - {len(live)} surface(s) CANNOT be executed from a proof run on this machine: "
                  "driving them needs a live agent session to invoke the slash command or load the "
                  "plugin. What ships and where it is registered IS checked (a structural defect is "
                  "a blocking finding); behaviour through them is NOT established here:")
            for s in sorted(live):
                print(f"      {s}")
        if rest:
            print(f"  - {len(rest)} declared surface(s) are not validated by this gate; they are "
                  "UNCHECKED, not passed:")
            for s in rest:
                print(f"      {s}")
    if not a.get("control_backed"):
        print("  - a judge lens has a deferred objection to a procedure's control case")
    if a.get("scope_retractions_unjustified"):
        print(f"  - {a['scope_retractions_unjustified']} claim scope reduction(s) with no recorded "
              "reason; a claim that got smaller without a justification is a finding")
    if not a.get("independently_reproduced"):
        print("  - not independently reproduced. Nothing in this repository can set that axis: "
              "self-attestation cannot establish independence, and only a third party reproducing "
              "the release bundle can. It is reported False rather than omitted.")
    return 1


def register(sub) -> None:
    def common(sp):
        sp.add_argument("--keyfile")
        sp.add_argument("--ledger")
        return sp

    r = common(sub.add_parser("retract", help="record a reasoned reduction in a claim's scope"))
    r.add_argument("--claim", required=True)
    r.add_argument("--field", required=True, choices=["surface", "aicm"])
    r.add_argument("--removed", required=True, nargs="+")
    r.add_argument("--reason", required=True,
                   help="why this is no longer asserted; a retraction without one is refused")
    # `fn`, not `func`: main.py dispatches on args.fn. Registered with the wrong key the parser
    # accepted the command, printed its help, and died with AttributeError on any real invocation —
    # a surface that exists and does not run, which is the defect this whole release is about. It
    # was only caught by a test that actually executed it.
    r.set_defaults(fn=cmd_claims_retract)

    p = common(sub.add_parser("prove", help="run proof procedures and record them"))
    g = p.add_mutually_exclusive_group()
    g.add_argument("--claim")
    g.add_argument("--milestone")
    p.add_argument("--allow-version-drift", action="store_true",
                   help="prove even though declared versions disagree with VERSION")
    p.set_defaults(fn=cmd_prove)

    c = sub.add_parser("claims", help="claim status")
    cs = c.add_subparsers(dest="claims_cmd", required=True)
    common(cs.add_parser("check", help="the release gate")).set_defaults(fn=cmd_claims_check)

    a = common(sub.add_parser("attest", help="the goal, in one command"))
    a.add_argument("--self", action="store_true", dest="self_", help="attest this toolchain")
    a.add_argument("--json", action="store_true")
    a.set_defaults(fn=cmd_attest)
