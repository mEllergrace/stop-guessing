#!/usr/bin/env python3
# build-ok: searched scripts/ and the CLI. `doctor` (cmd_ops.cmd_doctor) reports ONE ledger and does
# not name the keyid it was written under or say whether that key is holdable; `prove`/`attest`
# answer this properly but REFUSE without the chain key, which is exactly the situation this is for;
# `audit_verify.py` evaluates audit findings, `hygiene_sweep.py` repo structure. Nothing reports,
# with no key present, which key each ledger needs and what stands between here and GOAL MET. New,
# and deliberately read-only.
"""What stands between this repository and `GOAL MET`, answerable without the chain key.

`stop-guessing prove` is the real gate and refuses without a key — correctly, since an unkeyed
verifier sees 0 proven and reporting that as a verdict would misstate the project. But refusing also
means an operator with no key learns *nothing*, including the one thing they most need to know:
**which key is missing**. A keyid is designed to be disclosable ("says which key would verify it
without disclosing anything forgeable", `keys.keyid_of_ledger`), so it can be reported safely.

    python3 scripts/goal_status.py           # human-readable
    python3 scripts/goal_status.py --json    # machine-readable

Three sections, matching the three things `release_assured` needs (`prove/runner.py:842`):

1. **Keys** — every ledger, the keyid it was written under, and whether any available provider
   holds that key. A ledger whose key is absent cannot be verified, and the toolchain will report
   `chain broken at 0 ... edited in place` — false tampering, not damage.
2. **Surfaces** — every declared surface, split by whether a proof run *can* drive it.
   `runner.LIVE_SESSION_KINDS` (`plugin`, `skill`, `command`) cannot be driven from a proof run at
   all; `hook`, `cli` and `daemon` can.
3. **Verdict inputs** — what each of the three axes needs.

NEVER prints key material. Only keyids, which are public by construction.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from stop_guessing.attest.keys import keyid_of_ledger  # noqa: E402
from stop_guessing.prove import runner  # noqa: E402

#: The ledgers this project keeps, and what each is for. Both are reported because they are keyed
#: independently and one verifying says nothing about the other — the case that produced #90.
LEDGERS = (
    ("custody", REPO / ".stop-guessing" / "ledger" / "custody.jsonl",
     "runtime chain of custody — what the hooks recorded"),
    ("proofs", runner.DEFAULT_LEDGER,
     "the proof ledger every claim in docs/claims.yaml cites"),
)


def available_keyids() -> list[str]:
    """Keyids the current environment can actually produce. Never the material.

    `discover` returns only its single best pick, so asking it once cannot tell us whether some
    *other* provider holds the key a ledger needs. Each provider is therefore asked separately.
    """
    import os

    from stop_guessing.attest.keys import from_env, from_keychain, from_keyfile, installed_keyfile

    out = []
    account = os.environ.get("USER") or ""
    for got in (from_keychain(account) if account else None,
                from_keyfile(installed_keyfile()),
                from_env()):
        if got:
            out.append(got[0].keyid)
    return out


def key_report() -> list[dict]:
    have = available_keyids()
    rows = []
    for name, path, purpose in LEDGERS:
        kid = keyid_of_ledger(path) if path.exists() else None
        rows.append({
            "ledger": name,
            "path": str(path),
            "purpose": purpose,
            "exists": path.exists(),
            "written_under": kid,
            "key_available": bool(kid and kid in have),
            "available_keyids": have,
        })
    return rows


def surface_report() -> dict:
    """Every declared surface, split by whether any proof run could drive it."""
    claims = runner.load_claims()["claims"]
    driveable: dict[str, list[str]] = {}
    live_session: dict[str, list[str]] = {}
    for c in claims:
        for s in (c.get("surface") or []):
            kind = str(s).partition(":")[0]
            bucket = live_session if kind in runner.LIVE_SESSION_KINDS else driveable
            bucket.setdefault(str(s), []).append(c["id"])
    return {
        "driveable_by_a_proof_run": driveable,
        "requires_a_live_session": live_session,
        "live_session_kinds": list(runner.LIVE_SESSION_KINDS),
        "claims": len(claims),
    }


def build() -> dict:
    return {"keys": key_report(), "surfaces": surface_report()}


def _print(report: dict) -> int:
    blocked = 0
    print("KEYS")
    for r in report["keys"]:
        if not r["exists"]:
            print(f"  {r['ledger']:8} MISSING  {r['path']}")
            continue
        mark = "ok" if r["key_available"] else "UNAVAILABLE"
        print(f"  {r['ledger']:8} written under {r['written_under']}  [{mark}]")
        print(f"           {r['purpose']}")
        if not r["key_available"]:
            blocked += 1
            print(f"           Nothing here holds {r['written_under']}. Every entry will fail its")
            print("           MAC and the tool will report tampering that did not happen.")
    print(f"  available: {', '.join(report['keys'][0]['available_keyids']) or 'none'}")

    s = report["surfaces"]
    print(f"\nSURFACES ({s['claims']} claims)")
    print(f"  driveable by a proof run : {len(s['driveable_by_a_proof_run'])}")
    print(f"  need a live session      : {len(s['requires_a_live_session'])}"
          f"   (kinds: {', '.join(s['live_session_kinds'])})")
    for surface, claims in sorted(s["requires_a_live_session"].items()):
        print(f"      {surface:42} {', '.join(claims)}")

    print("\nVERDICT INPUTS  (release_assured, prove/runner.py:842)")
    print("  self_attestation_complete : needs a verifiable proof ledger — see KEYS")
    print("  surface_validated         : every surface above driven in a real process")
    print("  control_backed            : no judge control-present objection outstanding")
    return 1 if blocked else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    report = build()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    return _print(report)


if __name__ == "__main__":
    raise SystemExit(main())
