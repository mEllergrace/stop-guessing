"""`stop-guessing prove | claims | attest` — the goal surface."""

from __future__ import annotations

import json
from pathlib import Path

from stop_guessing.attest.keys import from_env, from_keyfile
from stop_guessing.ledger.chain import ChainKey
from stop_guessing.prove import runner
from stop_guessing.prove.registry import all_procedures


def _key(args) -> ChainKey | None:
    if getattr(args, "keyfile", None):
        got = from_keyfile(args.keyfile)
        if got:
            return got[0]
    got = from_env()
    return got[0] if got else None


def _ledger(args) -> Path:
    return Path(args.ledger) if getattr(args, "ledger", None) else runner.DEFAULT_LEDGER


def cmd_prove(args) -> int:
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
    result = runner.check(_key(args), _ledger(args))
    print(f"ledger: {result['ledger']}")
    print(f"chain : intact={result['chain_intact']} keyed={result['chain_keyed']}")
    if not result["chain_intact"]:
        print(f"        {result['chain_reason']}")
    print()
    for row in result["rows"]:
        if row["proven"]:
            mark = "PROVEN  "
        elif not row["has_procedure"]:
            mark = "NO-PROC "
        else:
            mark = "UNPROVEN"
        extra = ""
        if row["dead"]:
            extra = "  !! " + "; ".join(row["dead"])
        if not row["kind_matches"]:
            extra += "  !! procedure kind does not match the declared proof_kind"
        print(f"  {mark} {row['id']:<10} {str(row['milestone']):<4} "
              f"{row['proof_kind']:<12} {len(row['live'])} proof(s){extra}")
    print(f"\n{result['proven']}/{result['total']} claims proven")
    if not result["ok"]:
        print("A claim with no surviving proof is a FAILED claim, not an unassessed one.")
    return 0 if result["ok"] else 1


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
    return 1


def register(sub) -> None:
    def common(sp):
        sp.add_argument("--keyfile")
        sp.add_argument("--ledger")
        return sp

    p = common(sub.add_parser("prove", help="run proof procedures and record them"))
    g = p.add_mutually_exclusive_group()
    g.add_argument("--claim")
    g.add_argument("--milestone")
    p.set_defaults(fn=cmd_prove)

    c = sub.add_parser("claims", help="claim status")
    cs = c.add_subparsers(dest="claims_cmd", required=True)
    common(cs.add_parser("check", help="the release gate")).set_defaults(fn=cmd_claims_check)

    a = common(sub.add_parser("attest", help="the goal, in one command"))
    a.add_argument("--self", action="store_true", dest="self_", help="attest this toolchain")
    a.add_argument("--json", action="store_true")
    a.set_defaults(fn=cmd_attest)
