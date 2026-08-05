#!/usr/bin/env python3
# build-ok: searched /Users/isme/Software/repo-hygiene/run_hygiene.py — it is the FLEET driver and
# requires --db projectman.db plus a --dest-root scan of ~/DockProjects (an external drive that is
# routinely unmounted), so it cannot run against one working repo. This does not reimplement any
# check: it imports scan_tree, find_tracked_vendor_dirs and scan from repo-hygiene unchanged and
# only supplies the repo path they were already written to take. scripts/ holds attest_guard.py,
# which guards attestation and does no hygiene at all.
"""Run the repo-hygiene checks against THIS repo, without the fleet driver.

Same checks, same code, one repo:

    scripts/hygiene_sweep.py            # report
    scripts/hygiene_sweep.py --json     # machine-readable, for the workflow audit

Read-only by construction — every upstream check is a detector, and this adds no writes. Acting on
a finding is a separate, deliberate step, and any finding that moves a module should be run under
``attest_guard.py`` because module moves are the one change class that un-proves a claim.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HYGIENE = Path("/Users/isme/Software/repo-hygiene")
REPO = Path(__file__).resolve().parent.parent


def _checks(hygiene_root: Path | None = None):
    root = Path(hygiene_root or os.environ.get("REPO_HYGIENE_ROOT") or HYGIENE)
    if not root.is_dir():
        raise SystemExit(
            f"repo-hygiene is not at {root}. Clone https://github.com/moonsoup/repo-hygiene, "
            f"then pass --hygiene-root or set $REPO_HYGIENE_ROOT."
        )
    sys.path.insert(0, str(root))
    from checks.hardcoded_paths import scan_tree
    from checks.stale_docs import scan
    from checks.vendored_code import find_tracked_vendor_dirs

    return scan_tree, find_tracked_vendor_dirs, scan


def sweep(root: Path, patterns: list[str] | None = None,
          hygiene_root: Path | None = None) -> dict:
    scan_tree, find_tracked_vendor_dirs, stale_scan = _checks(hygiene_root)
    patterns = patterns or ["/Users/isme/Software", "/Users/isme/work"]
    hits = scan_tree(str(root), patterns)
    return {
        "repo": str(root),
        "hardcoded_paths": {rel: lines for rel, lines in sorted(hits.items())},
        "hardcoded_path_files": len(hits),
        "hardcoded_path_hits": sum(len(v) for v in hits.values()),
        "vendored_dirs": find_tracked_vendor_dirs(str(root)),
        "stale_docs": stale_scan(str(root)),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=str(REPO))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--hygiene-root", help="where repo-hygiene is checked out")
    args = ap.parse_args(argv)

    result = sweep(Path(args.root), hygiene_root=args.hygiene_root)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    print(f"hygiene sweep: {result['repo']}\n")
    hp = result["hardcoded_paths"]
    if hp:
        print(f"hardcoded-paths: {result['hardcoded_path_hits']} hit(s) "
              f"in {result['hardcoded_path_files']} file(s)")
        for rel, lines in list(hp.items())[:15]:
            print(f"   {rel} ({len(lines)} line(s))")
        if len(hp) > 15:
            print(f"   … and {len(hp) - 15} more file(s)")
    else:
        print("hardcoded-paths: clean")

    vd = result["vendored_dirs"]
    print(f"\nvendored-code: {len(vd)} tracked vendor dir(s)"
          if vd else "\nvendored-code: clean")
    for name, count in (vd or {}).items():
        print(f"   {name}: {count} tracked file(s)")

    sd = result["stale_docs"] or {}
    drift = sd.get("version_drift") or {}
    claims = sd.get("not_started_claims") or {}
    print(f"\nstale-docs: {len(drift)} version drift(s), {len(claims)} not-started claim(s)")
    for rel, (declared, expected) in list(drift.items())[:10]:
        print(f"   version-drift: {rel} says {declared}, VERSION says {expected}")
    for phrase, evidence in list(claims.items())[:10]:
        print(f"   not-started-claim: README says {phrase!r} but repo has {evidence}")

    total = result["hardcoded_path_hits"] + len(vd or {}) + len(drift) + len(claims)
    print(f"\nTOTAL: {total} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
