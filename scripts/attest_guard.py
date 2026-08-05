#!/usr/bin/env python3
# build-ok: searched stop_guessing/prove/runner.py (attest_self reports one state, never diffs two),
# stop_guessing/verify/sufficiency.py (per-regime completeness of a single record set),
# /Users/isme/Software/spindlebox/spindlebox/staleness.py (snapshot_files digests FILES for
# staleness — the wrong unit; a file can change with every claim still proven, and a claim can
# break with no file changing), and /Users/isme/Software/repo-hygiene/run_hygiene.py (read-only
# detectors, greps "not_started_claims" in README prose, entirely unaware of the ledger).
# scripts/ and .claude/commands/ are empty. Nothing compares two attestations for regression.
"""Make "without breaking attestation" mechanical instead of a promise.

Repo work — a hygiene sweep, an untracking, a refactor — is safe or unsafe depending on facts
nobody can hold in their head: 14 of this project's claims pin *module paths* in ``must_touch``,
so moving a module silently un-proves them, while deleting a build artifact breaks nothing at all
because every evidence ref is a ledger record id. The difference is invisible at the moment you
run ``git mv``.

So don't reason about it. Measure it:

    scripts/attest_guard.py --run "git rm -r --cached build"

Snapshots the attestation, runs the command, snapshots again, and reports what got *worse*. Exits
non-zero on any regression, so it composes into a shell chain or CI without anyone remembering to
read the output.

**This guards; it does not freeze.** A regression is not a veto — it is a list of what now needs
re-proving. The remedy for "CLAIM-09 was proven before this change" is ``prove --claim CLAIM-09``,
and only reverting when the claim genuinely cannot be re-proven. A tool that made the codebase
unchangeable would be the opposite of the point: this records custody, it does not withhold
permission.

**Only regressions.** An improvement is never reported, because a guard that also blocks progress
is a guard that gets switched off, and then it guards nothing.

The comparison is per-claim, never on the totals. One claim breaking while another is added nets
to zero on a count and is still a break — which is exactly the class of change a repo reorganise
produces.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def snapshot_of(attestation: dict) -> dict:
    """The invariants a repo change must not degrade, lifted out of a full attestation.

    Deliberately narrow. `attest --self` reports plenty that legitimately moves between runs —
    record counts, digests, timestamps — and a guard that treats motion as damage cries wolf.
    What must not move: which claims are proven, whether the chain verifies and is keyed, which
    AICM controls have evidence, and whether the workbook is bound.
    """
    caiq = attestation.get("caiq") or {}
    return {
        "chain_intact": bool(attestation.get("chain_intact")),
        "chain_keyed": bool(attestation.get("chain_keyed")),
        "chain_reason": attestation.get("chain_reason"),
        "proven_claims": sorted(
            r["id"] for r in (attestation.get("rows") or []) if r.get("proven")
        ),
        "controls_evidenced": sorted((attestation.get("aicm_controls_evidenced") or {}).keys()),
        "workbook_bound": bool(caiq.get("workbook_digest_bound")),
        "filled_from_proofs": bool(caiq.get("filled_from_proofs")),
        "goal_met": bool(attestation.get("goal_met")),
    }


def compare(before: dict, after: dict) -> list[str]:
    """What got worse. Empty means the change was attestation-neutral or better."""
    out: list[str] = []

    lost = sorted(set(before["proven_claims"]) - set(after["proven_claims"]))
    for claim in lost:
        out.append(f"{claim} was proven before this change and is not proven after it")

    dropped = sorted(set(before["controls_evidenced"]) - set(after["controls_evidenced"]))
    for ctrl in dropped:
        out.append(f"AICM {ctrl} lost its evidence")

    if before["chain_intact"] and not after["chain_intact"]:
        out.append(f"the ledger chain no longer verifies: {after.get('chain_reason')}")
    if before["chain_keyed"] and not after["chain_keyed"]:
        out.append("the ledger was keyed-verified before and is not after — a strength downgrade")
    if before["workbook_bound"] and not after["workbook_bound"]:
        out.append("the AI-CAIQ workbook is no longer bound to its proof")
    if before["filled_from_proofs"] and not after["filled_from_proofs"]:
        out.append("the AI-CAIQ is no longer filled from proofs")
    if before["goal_met"] and not after["goal_met"]:
        out.append("the project goal was met before this change and is not met after it")

    return out


def remedy(regressions: list[str]) -> list[str]:
    """What to run to re-bind, per finding. A guard that only says "no" teaches nothing."""
    out = []
    for r in regressions:
        claim = r.split()[0] if r.startswith("CLAIM-") else None
        if claim:
            out.append(f"stop-guessing prove --claim {claim}   # re-prove against the new code")
        elif "workbook" in r or "filled from proofs" in r:
            out.append("stop-guessing prove --claim CLAIM-21   # re-derive, re-fill, re-pin")
        elif "chain" in r:
            out.append("stop-guessing ledger verify            # the chain itself is damaged; "
                       "this is NOT re-provable, investigate before anything else")
    return list(dict.fromkeys(out))


def take(keyfile: str | None = None, ledger: str | None = None) -> dict:
    """Run the real attestation and reduce it to a snapshot."""
    cmd = [str(REPO / ".venv" / "bin" / "stop-guessing"), "attest", "--self", "--json"]
    if keyfile:
        cmd += ["--keyfile", keyfile]
    if ledger:
        cmd += ["--ledger", ledger]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO), timeout=1800)
    if not res.stdout.strip():
        raise SystemExit(f"attest produced no JSON (exit {res.returncode}): {res.stderr[-500:]}")
    try:
        return snapshot_of(json.loads(res.stdout))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"attest output was not JSON: {exc}\n{res.stdout[:500]}") from exc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", help="shell command to run between the two snapshots")
    ap.add_argument("--save", help="write the 'before' snapshot here and stop")
    ap.add_argument("--against", help="compare a fresh snapshot against this saved one")
    ap.add_argument("--keyfile")
    ap.add_argument("--ledger")
    args = ap.parse_args(argv)

    if args.save:
        before = take(args.keyfile, args.ledger)
        Path(args.save).write_text(json.dumps(before, indent=2), encoding="utf-8")
        print(f"baseline saved to {args.save}: "
              f"{len(before['proven_claims'])} proven claim(s), "
              f"{len(before['controls_evidenced'])} control(s) evidenced, "
              f"goal_met={before['goal_met']}")
        return 0

    if args.against:
        before = json.loads(Path(args.against).read_text(encoding="utf-8"))
    else:
        print("taking baseline snapshot…", file=sys.stderr)
        before = take(args.keyfile, args.ledger)

    if args.run:
        print(f"running: {args.run}", file=sys.stderr)
        res = subprocess.run(args.run, shell=True, cwd=str(REPO), env=dict(os.environ))
        if res.returncode != 0:
            print(f"the command itself failed (exit {res.returncode}); "
                  f"checking attestation anyway", file=sys.stderr)

    print("taking post-change snapshot…", file=sys.stderr)
    after = take(args.keyfile, args.ledger)

    regressions = compare(before, after)
    if not regressions:
        gained = sorted(set(after["proven_claims"]) - set(before["proven_claims"]))
        print("ATTESTATION INTACT — no claim, control, chain property or binding got worse")
        if gained:
            print(f"  improved: {', '.join(gained)} now proven")
        return 0

    print(f"ATTESTATION REGRESSED — {len(regressions)} finding(s):")
    for r in regressions:
        print(f"  - {r}")
    print("\nThis is a re-proving list, not a veto. To re-bind:")
    for cmd in remedy(regressions):
        print(f"  {cmd}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
