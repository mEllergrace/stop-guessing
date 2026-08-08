#!/usr/bin/env python3
# build-ok: searched scripts/ — depersonalise_paths.py rewrites filesystem PREFIXES in shipped source
# and explicitly protects IMPLEMENTATION_PLAN.md; stamp_version.py rewrites version strings only;
# hygiene_sweep.py and audit_verify.py are read-only. Nothing rewrites audience framing, and this
# must be able to touch the plan, which depersonalise_paths deliberately refuses to.
"""Remove framing that names one organisation as the primary user or target customer.

The owner's decision, recorded rather than inferred: this is a general-purpose chain-of-custody
toolchain, not a deliverable built for one company. The plan described "a tool CSA staff install
once", "the deliverable CSA staff expect", and "a public CSA-facing reference implementation", which
reads as a product with a single named customer.

**What is deliberately NOT touched.** CSA is the publisher of AICM and the AI-CAIQ, and this toolchain
genuinely maps to those and reads that workbook. Citing a standards body as the source of a framework
is not the same as naming it as the customer, and stripping those citations would make the
provenance worse, not more neutral. Likewise `csa.coc/` (a record annotation namespace already
written into signed ledger entries) and the `csa-material` classification label are technical
identifiers, not audience claims — renaming them would invalidate existing evidence, so they stay and
are reported instead.

This edits IMPLEMENTATION_PLAN.md, which `depersonalise_paths.py` refuses to touch. That refusal is
about not falsifying a provenance record by rewriting where assets were found. An owner changing the
stated audience of their own project is a different act, and it is recorded in IMPLEMENTATION_LOG.md
rather than made silently.

    python3 scripts/generalise_audience.py --check
    python3 scripts/generalise_audience.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: (pattern, replacement). Ordered — longer, more specific phrases first.
REWRITES = (
    (r"a tool CSA staff install once", "a tool an operator installs once"),
    (r"The deliverable CSA staff expect", "The published control framework this maps to"),
    (r"\*\*Tier 2 is the recommended install for CSA staff\*\*",
     "**Tier 2 is the recommended install for anyone holding sensitive material**"),
    (r"\*\*Install story for a CSA staffer\*\*", "**Install story for an operator**"),
    (r"Certifier identity for CSA distribution", "Certifier identity for distribution"),
    (r"the individual staffer as records custodian, or a central CSA role\?",
     "the individual operator as records custodian, or a central organisational role?"),
    (r"a public CSA-facing reference implementation", "a public reference implementation"),
    (r"a CSA staffer can obtain the template from CSA",
     "an operator can obtain the template from CSA"),
    (r"on a staff laptop", "on an operator's machine"),
)

#: Technical identifiers that contain the string and must NOT be rewritten, with why.
PROTECTED = {
    "csa.coc/": "record annotation namespace, already present in signed ledger entries",
    "csa-material": "classification label; renaming changes classification and invalidates proofs",
    "csa-roster": "a classify.yaml rule id referenced by recorded evidence",
    "/work/CSA/": "a path pattern in classify.yaml matched by existing proof records",
}

TARGETS = ("IMPLEMENTATION_PLAN.md", "README.md", "docs/index.html",
           "stop_guessing/prove/procedures.py", "IMPLEMENTATION_LOG.md")


def remaining(paths=None) -> dict[str, list[str]]:
    """Audience framing still present, per file."""
    out: dict[str, list[str]] = {}
    for rel in paths or TARGETS:
        p = REPO / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8")
        hits = [pat for pat, _ in REWRITES if re.search(pat, text)]
        if hits:
            out[rel] = hits
    return out


def rewrite(paths=None) -> dict[str, int]:
    changed: dict[str, int] = {}
    for rel in paths or TARGETS:
        p = REPO / rel
        if not p.is_file():
            continue
        new = p.read_text(encoding="utf-8")
        n = 0
        for pat, sub in REWRITES:
            new, k = re.subn(pat, sub, new)
            n += k
        if n:
            p.write_text(new, encoding="utf-8")
            changed[rel] = n
    return changed


def protected_present() -> dict[str, str]:
    """Technical identifiers found, reported so their survival is a decision and not an oversight."""
    found = {}
    for token, why in PROTECTED.items():
        hit = any(token in (REPO / rel).read_text(encoding="utf-8")
                  for rel in TARGETS if (REPO / rel).is_file())
        if hit:
            found[token] = why
    return found


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)

    if args.check:
        left = remaining()
        for rel, hits in left.items():
            print(f"{rel}: {len(hits)} audience-framing phrase(s) remain")
        if not left:
            print("no single-organisation audience framing remains")
        for token, why in protected_present().items():
            print(f"  PRESERVED {token} — {why}")
        return 1 if left else 0

    for rel, n in sorted(rewrite().items()):
        print(f"rewrote {rel} ({n} phrase(s))")
    print("\nPRESERVED deliberately — technical identifiers, not audience claims:")
    for token, why in protected_present().items():
        print(f"  {token} — {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
