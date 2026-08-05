#!/usr/bin/env python3
# build-ok: searched scripts/ (audit_verify.py verifies but files nothing; attest_guard.py,
# hygiene_sweep.py, stamp_version.py are unrelated), /Users/isme/Software/projectMan/scripts for a
# gh_issue helper (it targets projectMan's own tracker and takes a project id, not a findings list),
# and .github/ISSUE_TEMPLATE (forms for humans, not a bulk filer). Nothing files a verified findings
# set with its evidence, which is what "file the verified with evidence, as you go" needs.
"""File one GitHub issue per audit finding, carrying the evidence that verified it.

    scripts/file_audit_issues.py --dry-run     # show what would be filed
    scripts/file_audit_issues.py               # file the missing ones
    scripts/file_audit_issues.py --status PRESENT

**Idempotent.** Every title is prefixed with the finding id, and existing issues are read first, so
re-running files only what is missing. That matters because this runs again after fixes land: an
issue filer that duplicates on re-run makes the tracker useless exactly when it is being used most.

Evidence, not assertion. Each issue body carries the predicate's own output at a named commit, so a
reader can re-derive the finding rather than trust it — and `scripts/audit_verify.py --id <id>` is
in the body as the one command that re-checks it.

DYNAMIC findings are filed too, and labelled as unverified. The audit that produced them could not
execute anything, so they are inferences from source; filing them as confirmed defects would be the
same laundering of an inference into a result that this project exists to prevent.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from audit_verify import DYNAMIC, FINDINGS, PRESENT, head_commit, run_all  # noqa: E402

GH_REPO = "mEllergrace/stop-guessing"
AUDIT = "STOP-GUESSING_HARDENING_AUDIT_PASSOFF_2026-08-04"

SEVERITY_LABEL = {"CRITICAL": "bug", "HIGH": "bug", "MEDIUM": "enhancement"}


def existing_titles(repo: str = GH_REPO) -> set[str]:
    """Every issue title already on the tracker, open or closed."""
    res = subprocess.run(
        ["gh", "issue", "list", "--repo", repo, "--state", "all", "--limit", "500",
         "--json", "title"],
        capture_output=True, text=True, timeout=120,
    )
    if res.returncode != 0:
        raise SystemExit(f"could not list issues: {res.stderr[-400:]}")
    return {row["title"] for row in json.loads(res.stdout or "[]")}


def body_for(row: dict, commit: str) -> str:
    f = next((x for x in FINDINGS if x.id == row["id"]), None)
    files = "\n".join(f"- `{p}`" for p in (f.files if f else []))
    verified = (
        "**Status: CONFIRMED PRESENT** — re-derived from source by a predicate, not accepted from "
        "the report."
        if row["status"] == PRESENT else
        "**Status: UNVERIFIED (DYNAMIC)** — no static predicate settles this. The originating audit "
        "could not execute anything in its environment, so this is an inference from source and is "
        "filed as such. It needs a live adversarial test before it is treated as a defect."
    )
    return f"""{verified}

**Severity (as reported):** {row['severity']}

### Evidence
```
{row['evidence']}
```
Verified at commit `{commit}`.

### Where
{files}

### Re-check this one
```bash
scripts/audit_verify.py --id {row['id']}
```
The predicate answers only "is the defect still present". When a fix lands it flips to `ABSENT`,
and that flip is the reconfirmation — not a claim in a commit message.

### Provenance
From `{AUDIT}`, an independent static hardening audit of commit `ad166e8`. Findings were
re-verified against source before filing; two of the verifier's own predicates were found wrong
during that pass (one matched a word in a docstring, one matched a value in a `print`) and were
corrected, which is why the evidence above is a call-site or absence fact rather than a grep hit.
"""


def plan(status_filter: str | None = None) -> list[dict]:
    rows = run_all()
    if status_filter:
        rows = [r for r in rows if r["status"] == status_filter.upper()]
    else:
        rows = [r for r in rows if r["status"] in (PRESENT, DYNAMIC)]
    return rows


def title_for(row: dict) -> str:
    return f"{row['id']}: {row['title']}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--status", help="PRESENT or DYNAMIC only")
    ap.add_argument("--repo", default=GH_REPO)
    ap.add_argument("--limit", type=int, help="stop after this many (for a cautious first run)")
    args = ap.parse_args(argv)

    commit = head_commit()
    rows = plan(args.status)
    have = set() if args.dry_run else existing_titles(args.repo)
    if args.dry_run:
        try:
            have = existing_titles(args.repo)
        except SystemExit:
            have = set()

    todo = [r for r in rows if title_for(r) not in have]
    print(f"{len(rows)} finding(s) in scope, {len(rows) - len(todo)} already filed, "
          f"{len(todo)} to file")

    filed = 0
    for row in todo:
        if args.limit and filed >= args.limit:
            print(f"stopping at --limit {args.limit}")
            break
        title = title_for(row)
        labels = [SEVERITY_LABEL.get(row["severity"], "bug"), "hardening-audit"]
        if row["status"] == DYNAMIC:
            labels.append("needs-live-test")
        if args.dry_run:
            print(f"  WOULD FILE [{row['status']}] {title}  labels={','.join(labels)}")
            filed += 1
            continue
        cmd = ["gh", "issue", "create", "--repo", args.repo, "--title", title,
               "--body", body_for(row, commit)]
        for lab in labels:
            cmd += ["--label", lab]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode != 0:
            print(f"  FAILED {row['id']}: {res.stderr.strip()[-200:]}")
            continue
        print(f"  filed [{row['status']}] {title} -> {res.stdout.strip()}")
        filed += 1

    print(f"\n{'would file' if args.dry_run else 'filed'} {filed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
