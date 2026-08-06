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

REPO = Path(__file__).resolve().parent.parent

#: Where repo-hygiene might be, in precedence order. The default used to be a single absolute path
#: under one developer's home, so the shipped default worked for exactly one person — every other
#: reader had to discover `--hygiene-root` from a traceback. `--hygiene-root` and
#: `$REPO_HYGIENE_ROOT` are unchanged and still win; only the fallback got portable.
HYGIENE_SEARCH = (
    Path.cwd() / "repo-hygiene",
    REPO.parent / "repo-hygiene",              # a sibling checkout, the common layout
    Path.home() / "Software" / "repo-hygiene",
    Path.home() / "repo-hygiene",
)

#: Kept as a name because it was importable and something outside this repo may reference it.
HYGIENE = HYGIENE_SEARCH[1]


def _discover() -> Path | None:
    for cand in HYGIENE_SEARCH:
        if (cand / "checks").is_dir():
            return cand
    return None


#: Findings that are real but deliberate, with the reason. A census counts strings; it cannot know
#: intent, and a report that lists 165 "findings" against a clean repo teaches its reader to ignore
#: it — which is worse than not running it. Each entry here is a decision someone can disagree with,
#: stated once, rather than noise repeated every run.
DELIBERATE = {
    "IMPLEMENTATION_PLAN.md": ("records where each reused asset was found; rewriting the paths "
                               "would falsify the provenance record it exists to keep"),
    # A changelog entry that says "we removed X" has to be able to name X. Rewriting these would
    # produce "replaced /example/... with /example/...", which is not a record of anything.
    # `depersonalise_paths.py` already refuses to touch them; this is the detector agreeing with the
    # rewriter, and tests/test_hygiene_consistency.py pins that agreement so they cannot drift.
    "CHANGELOG.md": "names the paths it records having removed; rewriting would falsify the entry",
    "IMPLEMENTATION_LOG.md": "an append-only record of decisions, including which paths changed",
    "scripts/depersonalise_paths.py": ("holds the literal prefixes it searches for and replaces; "
                                       "a rewriter cannot name its input indirectly"),
    "scripts/test_depersonalise_paths.py": ("asserts that the old prefix is found and the new one "
                                           "classifies identically, so it must contain both"),
}


def _tracked(repo: Path) -> set:
    """Files git actually ships. An ignored artifact is not a hygiene finding about the product."""
    import subprocess as _sp

    try:
        out = _sp.run(["git", "ls-files"], capture_output=True, text=True,  # noqa: S603
                      cwd=str(repo), timeout=300)
    except (OSError, _sp.SubprocessError):
        return set()
    return {ln.strip() for ln in out.stdout.splitlines() if ln.strip()}


def _triage(hits: dict, repo: Path) -> tuple[dict, dict, dict]:
    """(shipped_and_unexplained, shipped_but_deliberate, not_shipped)."""
    tracked = _tracked(repo)
    real, deliberate, ignored = {}, {}, {}
    for rel, lines in (hits or {}).items():
        # `# build-ok:` provenance comments are required by check_before_build.sh, which demands a
        # reason of >=60 characters naming a searched path. Counting the evidence one project rule
        # mandates as a violation of another would make the two contradict each other.
        lines = [ln for ln in lines
                 if not str(ln[1] if isinstance(ln, tuple) else ln).lstrip().startswith("#")]
        if not lines:
            continue
        if rel not in tracked:
            ignored[rel] = lines
        elif any(rel == k or rel.endswith(k) for k in DELIBERATE):
            deliberate[rel] = lines
        else:
            real[rel] = lines
    return real, deliberate, ignored


def _checks(hygiene_root: Path | None = None):
    explicit = hygiene_root or os.environ.get("REPO_HYGIENE_ROOT")
    root = Path(explicit) if explicit else (_discover() or HYGIENE)
    if not root.is_dir():
        raise SystemExit(
            f"repo-hygiene is not at {root}. Clone https://github.com/moonsoup/repo-hygiene, "
            f"then pass --hygiene-root or set $REPO_HYGIENE_ROOT. Searched:\n  "
            + "\n  ".join(str(c) for c in HYGIENE_SEARCH)
        )
    sys.path.insert(0, str(root))
    from checks.hardcoded_paths import scan_tree
    from checks.stale_docs import scan
    from checks.vendored_code import find_tracked_vendor_dirs

    return scan_tree, find_tracked_vendor_dirs, scan


def sweep(root: Path, patterns: list[str] | None = None,
          hygiene_root: Path | None = None) -> dict:
    scan_tree, find_tracked_vendor_dirs, stale_scan = _checks(hygiene_root)
    # Derived from the running user's home, not one developer's. The hardcoded defaults meant the
    # hardcoded-paths check could only find hardcoded paths belonging to the person who wrote it —
    # which is a nice illustration of the defect and no use to anyone else.
    patterns = patterns or [str(Path.home() / "Software"), str(Path.home() / "work"),
                            str(Path.home() / "DockProjects")]
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
    real, deliberate, ignored = _triage(hp, Path(result["repo"]))
    if real:
        n = sum(len(v) for v in real.values())
        print(f"hardcoded-paths: {n} hit(s) in {len(real)} SHIPPED file(s) — these are findings")
        for rel, lines in list(real.items())[:15]:
            print(f"   {rel} ({len(lines)} line(s))")
        if len(real) > 15:
            print(f"   … and {len(real) - 15} more file(s)")
    else:
        print("hardcoded-paths: clean in every tracked file")
    if deliberate:
        print(f"   {len(deliberate)} tracked file(s) hold them deliberately, not counted:")
        for rel in sorted(deliberate):
            why = next(v for k, v in DELIBERATE.items() if rel == k or rel.endswith(k))
            print(f"     {rel} — {why}")
    if ignored:
        n = sum(len(v) for v in ignored.values())
        print(f"   {n} hit(s) in {len(ignored)} untracked file(s), which do not ship "
              f"({', '.join(sorted(ignored)[:3])}{'…' if len(ignored) > 3 else ''})")

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

    shipped = sum(len(v) for v in real.values()) + len(vd) + len(drift) + len(claims)
    print(f"\nTOTAL: {shipped} finding(s) in shipped files"
          + ("" if shipped else " — nothing a reader of this repository would inherit"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
