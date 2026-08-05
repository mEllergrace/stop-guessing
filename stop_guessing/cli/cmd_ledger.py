"""`stop-guessing ledger …` — write, verify, seal, inspect."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from stop_guessing.attest.keys import KeyUnavailable, from_keyfile
from stop_guessing.ledger import segments
from stop_guessing.ledger.alerts import alerts_from
from stop_guessing.ledger.chain import ChainKey
from stop_guessing.ledger.sink import LedgerError, load, record
from stop_guessing.version import config_dir


def _path(args) -> Path:
    """The ledger to operate on. #66: one resolver, and it names what it resolved."""
    from stop_guessing.version import installed_ledger

    return Path(_path(args)) if getattr(args, "path", None) else installed_ledger()


def _key(args: argparse.Namespace) -> ChainKey | None:
    """Resolve the chain key, or None when explicitly running unkeyed.

    ``--public`` means "verify what can be verified without the key" and is reported honestly as
    chain-only. It is not a way to make a broken ledger look fine.
    """
    if getattr(args, "public", False):
        return None
    if getattr(args, "keyfile", None):
        got = from_keyfile(args.keyfile)
        if got:
            return got[0]
        raise KeyUnavailable(f"no key in {args.keyfile}")
    # #66: the installed profile keeps its key in a mode-600 keyfile that install.sh writes.
    # Consulting only the environment meant the CLI reported chain-only on a ledger that is in
    # fact keyed — the user is told the evidence is weaker than it is, which is its own kind of
    # wrong answer. `discover()` is what every other surface uses.
    from stop_guessing.attest.keys import discover

    got = discover(config_dir=config_dir())
    return got[0] if got else None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def cmd_append(args: argparse.Namespace) -> int:
    event = {"op": args.op, "actor": args.actor, "detail": args.detail,
             "severity": args.severity, "at": _now()}
    if args.field:
        for kv in args.field:
            k, _, v = kv.partition("=")
            event[k] = v
    try:
        written = record(_path(args), event, _key(args))
    except LedgerError as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"seq={written['seq']} hash={written['hash'][:16]}… alg={written['hash_alg']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    key = _key(args)
    loaded = load(_path(args), key)
    v = loaded.chain

    if loaded.truncated:
        print(f"TRUNCATED: the final record in {_path(args)} is partial")
    if v.intact:
        if v.verified_keyed:
            print(f"PASS: {v.checked} records, chain intact and verified under its key")
        elif not loaded.entries:
            print("PASS: ledger is empty")
        else:
            print(
                f"PARTIAL: {v.checked} records, chain shape intact but keyed verification "
                "unavailable — report this as 'chain-only', never as tamper-proof"
            )
        return 0 if not loaded.truncated else 1

    print(f"FAIL: chain broken at entry {v.broken_at}")
    print(f"  {v.reason}")
    if v.broken_at is not None and v.broken_at < len(loaded.entries):
        e = loaded.entries[v.broken_at]
        print(f"  op={e.get('op')!r} actor={e.get('actor')!r} at={e.get('at')!r}")
    return 1


def cmd_seal(args: argparse.Namespace) -> int:
    try:
        s = segments.seal(
            _path(args), at=_now(), key=_key(args),
            prev_seal_digest=args.prev_seal or segments.GENESIS, index=args.index,
        )
    except LedgerError as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"sealed {s.segment}: {s.records} records, seq {s.first_seq}..{s.last_seq}")
    print(f"  head       {s.head_hash}")
    print(f"  file       {s.file_digest}")
    print(f"  seal digest {s.digest()}   <- the next segment chains to this")
    return 0


def cmd_verify_sealed(args: argparse.Namespace) -> int:
    result = segments.verify_sealed(_path(args), _key(args))
    if result["ok"]:
        print(f"PASS: sealed segment intact ({result['seal']['records']} records)")
        return 0
    print("FAIL: sealed segment does not verify")
    for f in result["findings"]:
        print(f"  - {f}")
    return 1


def cmd_tail(args: argparse.Namespace) -> int:
    loaded = load(_path(args), _key(args))
    for e in loaded.entries[-args.n :]:
        print(f"{e['seq']:>5}  {e.get('at', ''):<26} {str(e.get('op')):<22} "
              f"{str(e.get('actor'))[:28]:<28} {e['hash'][:12]}…")
    if not loaded.chain.intact:
        print(f"\nCHAIN BROKEN at {loaded.chain.broken_at}: {loaded.chain.reason}")
        return 1
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    loaded = load(_path(args), _key(args))
    found = alerts_from(loaded.entries, _key(args))
    if not found:
        print("no alerts")
        return 0
    for a in found:
        seq = a.entry.get("seq") if a.entry else "-"
        print(f"[{a.wake or 'note':<8}] seq={seq}  {a.reason}")
    return 1


def cmd_dump(args: argparse.Namespace) -> int:
    loaded = load(_path(args), _key(args))
    print(json.dumps(
        {"records": len(loaded.entries), "chain": loaded.chain.to_dict(),
         "truncated": loaded.truncated}, indent=2))
    return 0


def register(sub) -> None:
    p = sub.add_parser("ledger", help="the custody ledger")
    s = p.add_subparsers(dest="ledger_cmd", required=True)

    def common(sp):
        # #66: default to the ledger the installed hooks actually write, not a second location
        # nothing writes. --path still overrides for anyone pointing at an archive or a copy.
        sp.add_argument("--path", default=None,
                        help="ledger to read (default: the installed profile's custody ledger)")
        sp.add_argument("--keyfile", help="read the chain key from this file (mode 600)")
        sp.add_argument("--public", action="store_true",
                        help="verify without the key; reports chain-only, never tamper-proof")
        return sp

    a = common(s.add_parser("append", help="append one record"))
    a.add_argument("--op", required=True)
    a.add_argument("--actor", default="cli")
    a.add_argument("--detail", default="")
    a.add_argument("--severity", default="info", choices=["info", "warn", "critical"])
    a.add_argument("--field", action="append", help="extra k=v (repeatable)")
    a.set_defaults(fn=cmd_append)

    common(s.add_parser("verify", help="verify the chain")).set_defaults(fn=cmd_verify)
    common(s.add_parser("alerts", help="what a human should look at")).set_defaults(fn=cmd_alerts)
    common(s.add_parser("dump", help="chain verdict as JSON")).set_defaults(fn=cmd_dump)

    t = common(s.add_parser("tail", help="last records"))
    t.add_argument("-n", type=int, default=20)
    t.set_defaults(fn=cmd_tail)

    sl = common(s.add_parser("seal", help="seal and archive a segment"))
    sl.add_argument("--index", type=int, default=0)
    sl.add_argument("--prev-seal", help="digest of the preceding seal")
    sl.set_defaults(fn=cmd_seal)

    common(s.add_parser("verify-sealed", help="verify a sealed segment against its seal")
           ).set_defaults(fn=cmd_verify_sealed)
