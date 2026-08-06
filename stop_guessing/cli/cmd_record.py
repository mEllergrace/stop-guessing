"""`stop-guessing record emit` — M2's surface: build a record and show what the schema refuses.

CLAIM-05 declared `cli:"stop-guessing record emit"` and the command did not exist. The finding was
real; the fix I first reached for was to delete the declaration, which would have made the claim
smaller in the same breath as making the gate greener. That is the trade `prove/scope.py` exists to
catch, so the surface is built instead.

It composes what is already there — `CustodyRecord.build()` and `validate_tier_a()` — rather than
re-deriving the rules. A second copy of the Tier-A list would be a second thing to drift.

Three modes, because the interesting behaviour is the REFUSAL:

    record emit --fixture              a complete record, validated, printed as an in-toto Statement
    record emit --fixture --omit KEY   drop a Tier-A field and show the write being refused
    record emit --fixture --append     actually write it to a ledger, so the refusal is not theoretical

The distinction that matters, and the one M2 names: `alterations: []` is a positive assertion that
nothing was altered and is ACCEPTED; `alterations` absent means nobody looked and is REFUSED.
"""

from __future__ import annotations

import json
from pathlib import Path

from stop_guessing.ledger.entry import (
    TIER_A,
    CustodyRecord,
    RecordInvalid,
    validate_tier_a,
)
from stop_guessing.prove import runner


def _fixture() -> CustodyRecord:
    """A complete, Tier-A-valid record. Deliberately an `artifact.read` under `steer`."""
    now = runner._now()
    return CustodyRecord(
        op="artifact.read",
        agent_id="spiffe://local/claude-code/session/fixture/agent/main",
        runtime_action_id="toolu_fixture",
        operator={"identity": "fixture", "uid": 0, "host": "fixture"},
        session_id="sg-fixture",
        posture="steer",
        outcome="allow",
        channel="hookSpecificOutput.permissionDecision",
        at=now,
        recorded_at=now,
        record_id="coc:fixture",
        method_kind="direct-model",
        input_digest="sha256:" + "0" * 64,
        policy_set_digest="sha256:" + "1" * 64,
        determining_policy="10-base#allow-project-read",
        alterations=[],          # [] is the assertion; absence is the finding
        known_gaps=[],
    )


def _drop(obj: dict, path: str) -> None:
    cur = obj
    parts = path.split(".")
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return
        cur = cur[part]
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)


def cmd_record_emit(args) -> int:
    rec = _fixture()
    pred = rec.predicate()

    for path in args.omit or []:
        _drop(pred, path)

    findings = validate_tier_a(pred)
    if findings:
        print("REFUSED — the recorder will not write this record:")
        for f in findings:
            print(f"    {f}")
        print("\nA record missing a Tier-A field is not a weaker record, it is an unusable one: a "
              "reader cannot tell 'nothing was altered' from 'nobody looked'. In `steer`/`bar` the "
              "hook then fails CLOSED.")
        return 1

    stmt = rec.build() if not args.omit else {
        "_type": "https://in-toto.io/Statement/v1", "subject": [], "predicate": pred}

    if args.append:
        from stop_guessing.attest.keys import discover, keyid_of_ledger
        from stop_guessing.ledger.sink import record as _write

        ledger = Path(args.ledger) if args.ledger else runner.DEFAULT_LEDGER
        got = discover(getattr(args, "keyfile", None), prefer_keyid=keyid_of_ledger(ledger))
        if not got:
            print("REFUSED: no chain key. An unkeyed record is forgeable by the recorded party.")
            return 2
        try:
            entry = _write(ledger, {"op": "record.emit", "actor": "stop-guessing/record-emit",
                                    "at": runner._now(), "severity": "info",
                                    "detail": json.dumps({"fixture": True}),
                                    "known_gaps": [], "alterations": []}, got[0])
        except Exception as exc:  # noqa: BLE001 - the sink's own refusal is the answer
            print(f"REFUSED by the sink: {exc}")
            return 1
        print(f"appended: {runner.proof_ref(entry)}")
        return 0

    print(json.dumps(stmt, indent=2, sort_keys=True))
    print(f"\nvalidated against {len(TIER_A)} Tier-A fields — writable.", flush=True)
    print("`alterations: []` was ACCEPTED: it asserts nothing was altered. Re-run with "
          "`--omit alterations` to see the same record refused.")
    return 0


def register(sub) -> None:
    r = sub.add_parser("record", help="build and validate a custody record")
    rs = r.add_subparsers(dest="record_cmd", required=True)
    e = rs.add_parser("emit", help="emit a fixture record and show what the schema refuses")
    e.add_argument("--fixture", action="store_true",
                   help="use the built-in fixture (the only source today)")
    e.add_argument("--omit", action="append", metavar="PATH",
                   help="drop a Tier-A field (e.g. --omit alterations) to see the refusal")
    e.add_argument("--append", action="store_true", help="write it to the ledger")
    e.add_argument("--ledger")
    e.add_argument("--keyfile")
    e.set_defaults(fn=cmd_record_emit)


__all__ = ["cmd_record_emit", "register", "RecordInvalid"]
