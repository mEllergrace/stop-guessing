"""`verify`, `doctor`, `state`, `delegate`, `run`, `trust`, `policy`.

**Fixes #32.** These libraries all existed and worked; none had a CLI surface, while the shipped
`/custody` documentation told users to run `stop-guessing verify --sufficiency`. A user following
the installed docs got an argparse error. That is the same integration-truth failure as #13 one
layer up: the capability is real, the surface users are pointed at is not.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from stop_guessing.attest.keys import discover
from stop_guessing.version import policy_dir, repo_root


def _key(args):
    # discover(), not from_env(): an installed profile keeps its key in a
    # mode-600 keyfile that install.sh writes, and looking only at the
    # environment meant that key was never found. --keyfile still wins.
    got = discover(getattr(args, "keyfile", None))
    return got[0] if got else None


def _config_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))


def _default_ledger() -> Path:
    return _config_dir() / "stop-guessing" / "ledger" / "custody.jsonl"


# ── verify --sufficiency ─────────────────────────────────────────────────────


def cmd_verify(args) -> int:
    from stop_guessing.ledger.sink import load
    from stop_guessing.verify.sufficiency import assess, format_report

    path = Path(args.path) if args.path else _default_ledger()
    loaded = load(path, _key(args))
    if not loaded.chain.intact:
        print(f"FAIL: chain broken at entry {loaded.chain.broken_at} — {loaded.chain.reason}")
        print("      Sufficiency of a ledger that does not verify is not a meaningful question.")
        return 1
    if not args.sufficiency:
        print(f"PASS: {loaded.chain.checked} records, chain intact "
              f"({'keyed' if loaded.chain.verified_keyed else 'chain-only'})")
        return 0
    result = assess(loaded.entries)
    print(format_report(result))
    return 0 if result["verdict"] == "sufficient" else 1


# ── doctor ───────────────────────────────────────────────────────────────────


def cmd_doctor(args) -> int:
    from stop_guessing.compat import manifest
    from stop_guessing.recorder.guard import self_check
    from stop_guessing.recorder.network import audit

    cfg = _config_dir()
    print(f"profile     : {cfg}")
    rc = 0

    m = manifest.verify()
    print(f"vendored    : {'intact' if m['intact'] else 'DRIFTED'} ({len(m['ok'])} files)")
    if not m["intact"]:
        rc = 1
        for bucket in ("changed", "missing", "untracked"):
            for n in m[bucket]:
                print(f"              {bucket.upper()} {n}")

    manifest_path = cfg / "stop-guessing" / "install-manifest.json"
    install_manifest = None
    if manifest_path.is_file():
        try:
            install_manifest = json.loads(manifest_path.read_text())
        except ValueError:
            print("install     : manifest is not valid JSON")
            rc = 1
    # #46 (SG-HARD-012). doctor passed neither the settings file, the pinned registration command,
    # nor any daemon state into self_check(), so the tier it PRINTED could never exceed 0 and
    # registration pinning was skipped entirely — it reported on an architecture it had not
    # looked at. It now hands over what it can actually observe.
    settings = None
    settings_path = cfg / "settings.json"
    if settings_path.is_file():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except ValueError:
            print("settings    : settings.json is not valid JSON")
            rc = 1
    pinned = (install_manifest or {}).get("pinned_command")

    from stop_guessing.recorder.client import daemon_info, isolation_tier

    info = daemon_info(cfg)
    tier, why = isolation_tier(cfg)
    print(f"daemon      : {'running pid ' + str(info.get('pid')) + ' uid ' + str(info.get('uid')) if info else 'not running'}")
    print(f"isolation   : tier {tier} — {why}")

    rep = self_check(
        argv0=sys.argv[0], manifest=install_manifest,
        root=cfg / "hooks" if install_manifest else None,
        ledger_dir=_default_ledger().parent,
        settings=settings, pinned_command=pinned,
    )
    print(f"recorder    : tier {rep.isolation_tier}, "
          f"{'ok' if rep.ok else str(len(rep.findings)) + ' finding(s)'}")
    for f in rep.findings:
        print(f"              {f}")
    if not rep.ok:
        rc = 1

    net = audit(repo_root() / "stop_guessing")
    print(f"network     : {'offline' if net['offline_by_default'] else 'UNEXPECTED CALL SITES'} "
          f"({net['files_scanned']} modules scanned — source audit, not proof)")
    if not net["offline_by_default"]:
        rc = 1

    from stop_guessing.ledger.sink import load
    led = _default_ledger()
    if led.is_file():
        loaded = load(led, _key(args))
        state = ("intact, keyed" if loaded.chain.verified_keyed else
                 "intact, chain-only" if loaded.chain.intact else
                 f"BROKEN at {loaded.chain.broken_at}")
        print(f"ledger      : {len(loaded.entries)} records, {state}")
        if not loaded.chain.intact:
            rc = 1
    else:
        print("ledger      : none yet (no tool call has been recorded in this profile)")

    hooks = cfg / "hooks"
    for h in ("coc_gate.sh", "coc_post.sh"):
        print(f"hook        : {h} {'installed' if (hooks / h).is_file() else 'NOT INSTALLED'}")
    print(f"\n{'PASS' if rc == 0 else 'FINDINGS'}")
    return rc


# ── state ────────────────────────────────────────────────────────────────────


def cmd_state(args) -> int:
    from stop_guessing.ledger.sink import load
    from stop_guessing.taint import persist
    from stop_guessing.taint.state import rebuild

    records = load(_default_ledger(), _key(args)).entries if _default_ledger().is_file() else []
    authoritative = rebuild(records, args.session)
    cached = persist.load(args.session)

    print(f"session     : {args.session}")
    print(f"ledger      : {authoritative.summary()}")
    print(f"  digest    : {authoritative.digest}")
    print(f"cache       : {cached.summary()}")
    print(f"  digest    : {cached.digest}")
    agreed = cached.digest == authoritative.digest
    print(f"agreement   : {'yes' if agreed else 'NO — the ledger wins'}")
    if args.rebuild and not agreed:
        persist.save(authoritative)
        print("cache rewritten from the ledger")
    for aid, ref in sorted(authoritative.sources.items()):
        print(f"  {aid}  {','.join(sorted(ref.labels)):<28} {ref.path}")
    return 0 if agreed else 1


# ── delegate / run ───────────────────────────────────────────────────────────


def cmd_delegate(args) -> int:
    from stop_guessing.delegate import DelegationRefused, run_test, scaffold

    try:
        d = scaffold(args.dir, args.name, args.intent)
    except DelegationRefused as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"wrote {d.script}")
    print(f"wrote {d.test}")
    print("\nImplement handle(), then:")
    print(f"  stop-guessing run {d.script} --artifact <path>")
    print("\nThe test must pass before the script touches live data. It fails now, on purpose:")
    res = run_test(d)
    print(f"  test: {'PASS' if res['passed'] else 'fails while handle() is a stub'}")
    return 0


def cmd_run(args) -> int:
    from stop_guessing.delegate import Delegation, DelegationRefused, run, run_test, verify_script

    script = Path(args.script)
    d = Delegation(script.stem, script, script.parent / f"test_{script.stem}.py", args.intent or "")
    key = _key(args)
    if args.signed:
        if key is None:
            print("REFUSED: --signed needs a key to verify against")
            return 2
        ok, why = verify_script(script, key.material)
        print(f"signature: {'ok' if ok else 'REFUSED'} — {why}")
        if not ok:
            return 2
    try:
        res = run_test(d)
        print(f"test: {'PASS' if res['passed'] else 'FAIL'} ({res.get('tail', '')})")
        out = run(d, args.artifact or [])
    except DelegationRefused as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"exit {out['exit_code']}, network={out['sandbox']['network']}")
    print(out["output"].rstrip())
    return out["exit_code"]


# ── trust (vendored no-noodles CLI, unchanged) ───────────────────────────────


def cmd_trust(args) -> int:
    from stop_guessing.compat.manifest import vendored_dir

    gst = vendored_dir() / "grant_session_trust.sh"
    if not gst.is_file():
        print("grant_session_trust.sh is not in the vendored tree")
        return 1
    res = subprocess.run(["bash", str(gst), args.verb], timeout=30)  # noqa: S603
    return res.returncode


# ── policy ───────────────────────────────────────────────────────────────────


def cmd_policy(args) -> int:
    from stop_guessing.policy.engine import load, to_cedar

    ps = load(policy_dir())
    if args.export == "cedar":
        print(to_cedar(ps))
        return 0
    print(f"{len(ps.policies)} policies, set digest {ps.digest}")
    for p in ps.policies:
        scope = []
        if p.postures:
            scope.append("postures=" + ",".join(p.postures))
        if p.actions:
            scope.append("actions=" + ",".join(p.actions))
        print(f"  {p.effect:<7} {p.id:<44} {' '.join(scope)}")
    return 0


def cmd_export(args) -> int:
    """Render the ledger into an established evidence structure."""
    import json as _json

    from stop_guessing.ledger.sink import load
    from stop_guessing.prov import export_case, export_otel, export_prov

    path = Path(args.path) if args.path else _default_ledger()
    loaded = load(path, _key(args))
    if not loaded.chain.intact:
        print(f"REFUSED: chain broken at {loaded.chain.broken_at} — {loaded.chain.reason}")
        print("         Exporting a ledger that does not verify would launder it into a format "
              "that looks authoritative.")
        return 1
    # #80 (SG-HARD-047): a truncated ledger has an INTACT PREFIX, so this check passed it. PROV,
    # CASE/UCO and OTel all carry an authority the source no longer has once part of it is missing,
    # and a downstream validator has no way to tell a complete graph from a prefix of one. Same
    # rule as the chain break: refuse rather than launder.
    if loaded.corrupt:
        where = loaded.malformed_at or loaded.decode_error_at
        print(f"REFUSED: the ledger is corrupted at line {where} — damage an interrupted write "
              "cannot explain. Exporting it would render tampered input as evidence.")
        return 1
    if loaded.truncated:
        print("REFUSED: the ledger's final record is partial, so this is a prefix, not a ledger.")
        print("         The prefix verifies, which is exactly why exporting it is dangerous: the "
              "output would be indistinguishable from complete evidence.")
        return 1
    fmt = {"prov": export_prov.export, "case": export_case.export,
           "otel": export_otel.export}[args.format]
    out = fmt(loaded.entries)
    text = _json.dumps(out, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out} ({len(loaded.entries)} records as {args.format})")
    else:
        print(text)
    return 0


def register(sub) -> None:
    def common(sp):
        sp.add_argument("--keyfile")
        return sp

    v = common(sub.add_parser("verify", help="verify the chain, and optionally its sufficiency"))
    v.add_argument("--sufficiency", action="store_true",
                   help="assess whether the ledger answers governance questions")
    v.add_argument("--path", help="ledger path (defaults to the profile's custody ledger)")
    v.set_defaults(fn=cmd_verify)

    common(sub.add_parser("doctor", help="check the installation and the recorder")
           ).set_defaults(fn=cmd_doctor)

    st = common(sub.add_parser("state", help="compare ledger-derived state against the cache"))
    st.add_argument("session")
    st.add_argument("--rebuild", action="store_true", help="rewrite the cache from the ledger")
    st.set_defaults(fn=cmd_state)

    d = sub.add_parser("delegate", help="scaffold a script/test pair for data handling")
    dsub = d.add_subparsers(dest="delegate_cmd", required=True)
    dn = dsub.add_parser("new", help="write the pair")
    dn.add_argument("name")
    dn.add_argument("--intent", required=True)
    dn.add_argument("--dir", default="scripts")
    dn.set_defaults(fn=cmd_delegate)

    r = common(sub.add_parser("run", help="run a delegated script over artifacts"))
    r.add_argument("script")
    r.add_argument("--artifact", action="append")
    r.add_argument("--intent")
    r.add_argument("--signed", action="store_true", help="require a valid signature (bar posture)")
    r.set_defaults(fn=cmd_run)

    t = sub.add_parser("trust", help="session trust (no-noodles CLI, unchanged)")
    t.add_argument("verb", choices=["grant", "revoke", "status"])
    t.set_defaults(fn=cmd_trust)

    ex = common(sub.add_parser("export", help="render the ledger as PROV, CASE/UCO or OTel"))
    ex.add_argument("format", choices=["prov", "case", "otel"])
    ex.add_argument("--path", help="ledger path")
    ex.add_argument("--out", help="write here instead of stdout")
    ex.set_defaults(fn=cmd_export)

    pol = sub.add_parser("policy", help="show or export the policy set")
    pol.add_argument("--export", choices=["cedar"])
    pol.set_defaults(fn=cmd_policy)
