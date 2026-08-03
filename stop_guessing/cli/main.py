"""STOP-GUESSING command line.

Only the M0 surface exists: version, the vendored-tree manifest, and the compatibility gate.
Every other subcommand named in IMPLEMENTATION_PLAN.md is deliberately absent rather than
stubbed to return success — a command that pretends to work is the failure mode this project
exists to eliminate.
"""

from __future__ import annotations

import argparse
import json
import sys

from stop_guessing.version import __version__, repo_root

GOLDEN = "fixtures/compat-golden.json"


def _cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return 0


def _cmd_manifest(args: argparse.Namespace) -> int:
    from stop_guessing.compat import manifest

    if args.write:
        path = manifest.write()
        print(f"wrote {path.relative_to(repo_root())} ({len(manifest.load())} files)")
        return 0
    result = manifest.verify()
    print(f"vendored no-noodles: {len(result['ok'])} ok")
    for bucket in ("changed", "missing", "untracked"):
        for name in result[bucket]:
            print(f"  {bucket.upper():<9} {name}")
    if result["intact"]:
        print("PASS: vendored tree matches MANIFEST.sha256")
        return 0
    print("FAIL: vendored tree drifted — see moonsoup/no-noodles and do not auto-repair")
    return 1


def _cmd_compat_verify(args: argparse.Namespace) -> int:
    from stop_guessing.compat.corpus import CORPUS
    from stop_guessing.compat.replay import normalise, replay_all, summarise

    golden_path = repo_root() / GOLDEN

    print(f"replaying {len(CORPUS)} cases through the vendored hooks…", file=sys.stderr)
    outcomes = replay_all(CORPUS)
    observed = normalise(outcomes)
    stats = summarise(outcomes)

    if args.record_golden:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(
            json.dumps(
                {
                    "_note": (
                        "Observed behaviour of the vendored no-noodles hooks. Recorded, not "
                        "asserted. A diff here is a finding: either upstream changed or the "
                        "dispatcher diverged."
                    ),
                    "_stop_guessing_version": __version__,
                    "_cases": stats["cases"],
                    "_invocations": stats["invocations"],
                    "outcomes": observed,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"recorded {stats['invocations']} invocations across {stats['cases']} cases")
        print(f"  blocked (exit 2): {stats['blocked']}")
        if stats["unexpected_exit"]:
            print(f"  UNEXPECTED exit codes: {stats['unexpected_exit']}")
        print(f"  -> {golden_path.relative_to(repo_root())}")
        return 0

    if not golden_path.exists():
        print(f"FAIL: no golden at {GOLDEN}. Run `stop-guessing compat verify --record-golden`.")
        return 1

    expected = json.loads(golden_path.read_text(encoding="utf-8"))["outcomes"]
    diffs = []
    for key in sorted(set(expected) | set(observed)):
        if key not in expected:
            diffs.append((key, "NEW", None, observed[key]))
        elif key not in observed:
            diffs.append((key, "GONE", expected[key], None))
        elif expected[key] != observed[key]:
            diffs.append((key, "CHANGED", expected[key], observed[key]))

    if not diffs:
        print(f"PASS: {stats['invocations']} invocations identical to golden "
              f"({stats['cases']} cases, {stats['blocked']} blocked)")
        return 0

    print(f"FAIL: {len(diffs)} divergence(s) from golden")
    for key, kind, exp, obs in diffs[: args.max_diffs]:
        print(f"\n  {kind}  {key}")
        if exp is not None:
            print(f"    expected exit={exp['exit_code']} stdout={exp['stdout'][:160]!r}")
        if obs is not None:
            print(f"    observed exit={obs['exit_code']} stdout={obs['stdout'][:160]!r}")
    if len(diffs) > args.max_diffs:
        print(f"\n  … {len(diffs) - args.max_diffs} more")
    return 1


def _cmd_corpus_list(_: argparse.Namespace) -> int:
    from stop_guessing.compat.corpus import CORPUS

    for c in CORPUS:
        rep = f" x{c.repeat}" if c.repeat > 1 else ""
        note = f"  # {c.note}" if c.note else ""
        print(f"{c.id:<28} {c.tool:<6}{rep}{note}")
    print(f"\n{len(CORPUS)} cases")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stop-guessing",
        description="Chain of custody and data provenance for agentic AI.",
        epilog="Aliases: coc-prov, coc. Plan: IMPLEMENTATION_PLAN.md",
    )
    p.add_argument("--version", action="version", version=f"stop-guessing {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version", help="print the version").set_defaults(fn=_cmd_version)

    m = sub.add_parser("manifest", help="verify (or write) the vendored no-noodles manifest")
    m.add_argument("--write", action="store_true", help="regenerate MANIFEST.sha256")
    m.set_defaults(fn=_cmd_manifest)

    compat = sub.add_parser("compat", help="no-noodles compatibility")
    csub = compat.add_subparsers(dest="compat_cmd", required=True)

    v = csub.add_parser("verify", help="replay the corpus and compare against the golden")
    v.add_argument("--record-golden", action="store_true", help="record instead of compare")
    v.add_argument("--max-diffs", type=int, default=10)
    v.set_defaults(fn=_cmd_compat_verify)

    csub.add_parser("corpus", help="list the corpus").set_defaults(fn=_cmd_corpus_list)

    from stop_guessing.cli import cmd_ledger

    cmd_ledger.register(sub)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
