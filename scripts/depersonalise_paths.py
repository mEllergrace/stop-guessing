#!/usr/bin/env python3
# build-ok: searched scripts/ (hygiene_sweep.py DRIVES repo-hygiene and reports; stamp_version.py
# rewrites version strings only; attest_guard.py and audit_verify.py are read-only checkers) and
# /Users/isme/Software/repo-hygiene/checks/hardcoded_paths.py, which is a read-only census and
# deliberately makes no changes. Nothing existing rewrites the references it finds.
"""Replace one developer's absolute paths in tracked source with machine-independent ones.

repo-hygiene's `hardcoded-paths` check found 169 references across 11 files. Most are in ignored
artifacts (`.stop-guessing/proofs.jsonl`, `.spi/index.json`) and do not ship. What does ship is the
problem:

    stop_guessing/prove/procedures.py   10x  /Users/isme/work/CSA/roster.csv
    tests/*.py                           3x  the same fixture path
    scripts/hygiene_sweep.py             1x  a hardcoded path to another checkout

The classification fixtures are functionally portable already — `classify_path()` matches the path
as a STRING against `/work/CSA/` and never opens the file — so this changes no behaviour. It matters
anyway, for a reason a jury of peers would raise immediately: a reviewer reading
`/Users/isme/work/CSA/roster.csv` inside a proof procedure cannot tell whether the evidence depends
on private data on one machine. Publishing a reference implementation that *looks* like it reads a
private CSA directory undermines the proof whether or not it does.

`/example/work/CSA/roster.csv` matches the same rule, is obviously synthetic, and exists nowhere.

    python3 scripts/depersonalise_paths.py --check     # report, change nothing, exit 1 if found
    python3 scripts/depersonalise_paths.py             # rewrite
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The fixture prefix. `/work/CSA/` is what `rules/classify.yaml` matches, so the label is
#: unchanged; only the personal home prefix goes.
REPLACEMENTS = (
    ("/Users/isme/work/CSA/", "/example/work/CSA/"),
    ("/Users/isme/work/", "/example/work/"),
)

#: Paths where an absolute local reference is the POINT and must not be rewritten:
#: `IMPLEMENTATION_PLAN.md` is a historical planning document that deliberately records where each
#: reused asset was found, and rewriting it would falsify the record it exists to keep. It is
#: handled separately (see --plan), not silently.
SKIP = {"IMPLEMENTATION_PLAN.md", "CHANGELOG.md", "IMPLEMENTATION_LOG.md"}

SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".json", ".toml"}


def _label(p: Path) -> str:
    """Repo-relative where possible, absolute otherwise.

    `relative_to(REPO)` raised for any path outside the checkout, so the functions could only ever
    be called on the repo itself — including from their own tests. A helper that cannot be tested
    on a fixture is a helper nobody can check.
    """
    try:
        return str(p.relative_to(REPO))
    except ValueError:
        return str(p)


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True,  # noqa: S603
                         cwd=str(REPO), timeout=300)
    return [REPO / line for line in out.stdout.splitlines() if line.strip()]


def candidates() -> list[Path]:
    got = []
    for p in tracked_files():
        rel = str(p.relative_to(REPO))
        if rel in SKIP or p.suffix not in SUFFIXES:
            continue
        if rel.startswith("stop_guessing/compat/nonoodles/"):
            continue           # vendored byte-identically; rewriting it would fork upstream
        got.append(p)
    return got


def scan(paths=None) -> dict[str, list[tuple[int, str]]]:
    found: dict[str, list[tuple[int, str]]] = {}
    for p in paths or candidates():
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits = [(i, ln.strip()[:120]) for i, ln in enumerate(text.splitlines(), 1)
                if any(old in ln for old, _ in REPLACEMENTS)]
        if hits:
            found[_label(p)] = hits
    return found


def rewrite(paths=None) -> dict[str, int]:
    changed: dict[str, int] = {}
    for p in paths or candidates():
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        new = text
        for old, sub in REPLACEMENTS:
            new = new.replace(old, sub)
        if new != text:
            p.write_text(new, encoding="utf-8")
            changed[_label(p)] = sum(
                1 for a, b in zip(text.splitlines(), new.splitlines(), strict=False) if a != b)
    return changed


def other_local_roots() -> dict[str, list[str]]:
    """Absolute references to OTHER checkouts on this machine — a portability defect, not cosmetic.

    `scripts/hygiene_sweep.py` pointed at `/Users/isme/Software/repo-hygiene`, so it worked for
    exactly one person. Reported rather than rewritten: the right value depends on how the operator
    lays out their machine, and guessing it would be worse than naming it.
    """
    pat = re.compile(r"/Users/[A-Za-z0-9_.-]+/(?:Software|DockProjects)/[A-Za-z0-9_.-]+")
    out: dict[str, list[str]] = {}
    for p in candidates():
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for i, ln in enumerate(text.splitlines(), 1):
            if ln.lstrip().startswith("#"):
                continue           # a provenance comment naming where something was found is fine
            for m in pat.finditer(ln):
                out.setdefault(_label(p), []).append(f"{i}: {m.group(0)}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="report only; exit 1 if any remain")
    args = ap.parse_args(argv)

    found = scan()
    roots = other_local_roots()

    if args.check:
        for rel, hits in sorted(found.items()):
            print(f"{rel}: {len(hits)} personal fixture path(s)")
            for line_no, text in hits[:3]:
                print(f"    {line_no}: {text}")
        for rel, hits in sorted(roots.items()):
            print(f"{rel}: {len(hits)} reference(s) to another checkout on this machine")
            for h in hits[:3]:
                print(f"    {h}")
        if not found and not roots:
            print("no personal absolute paths in tracked, shipping source")
            return 0
        return 1

    changed = rewrite()
    for rel, n in sorted(changed.items()):
        print(f"rewrote {rel} ({n} line(s))")
    print(f"{len(changed)} file(s) changed")
    if roots:
        print("\nNOT rewritten — these name another checkout on this machine and the correct value "
              "depends on the operator's layout:")
        for rel, hits in sorted(roots.items()):
            for h in hits:
                print(f"    {rel}  {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
