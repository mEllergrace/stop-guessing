#!/usr/bin/env python3
# build-ok: searched scripts/ (attest_guard.py compares two attestations, audit_verify.py re-checks
# audit findings, file_audit_issues.py files them, hygiene_sweep.py runs repo-hygiene, stamp_version
# stamps manifests) and stop_guessing/attest/ (statement/dsse/bundle build in-toto envelopes for
# LEDGER records, not for a release artifact set). Nothing assembles a third-party-verifiable
# release bundle, which is the one thing `independently_reproduced` needs and no other tool here
# produces.
"""Assemble a release bundle a third party can verify WITHOUT the signing key.

`independently_reproduced` is the one assurance axis this repository cannot set about itself, and
that is correct: self-attestation cannot establish independent reproduction. What it CAN do is
stop being the obstacle — publish exactly what someone else needs to reach the same verdict, in a
form where their disagreement is meaningful.

    scripts/release_bundle.py            # build dist/release-bundle.json
    scripts/release_bundle.py --verify   # check a bundle the way a third party would

The bundle is deliberately **not** a claim that the software is correct. It is a claim about
identity and derivation:

  * the exact bytes of the release subject (wheel, sdist, plugin tree, policy, rules, claims);
  * the attestation those bytes produced, including which axes were false;
  * the audit-finding status with its confidence split, so a reader sees how many ABSENTs rest on
    structure alone;
  * the commands to re-derive all of it.

**Verification requires no secret.** Every digest is over public bytes, so a third party recomputes
them and compares. Where a chain key IS required — verifying the proof ledger — the bundle says so
rather than pretending the check is complete without it. A bundle that could only be verified by
the party that made it would establish nothing.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BUNDLE = REPO / "dist" / "release-bundle.json"

#: Files whose exact bytes define the release subject. A verifier recomputes every one.
SUBJECT_GLOBS = (
    "VERSION",
    "pyproject.toml",
    "docs/claims.yaml",
    "docs/audit-status.json",
    "stop_guessing/**/*.py",
    "stop_guessing/data/**/*.yaml",
    ".claude-plugin/**/*.json",
    ".claude-plugin/**/bin/*",
    "install.sh",
)


def _digest(p: Path) -> str:
    import hashlib

    return hashlib.sha256(p.read_bytes()).hexdigest()


def subject(root: Path = REPO) -> dict[str, str]:
    """Every file whose bytes the release consists of, digested."""
    out: dict[str, str] = {}
    for pattern in SUBJECT_GLOBS:
        for f in sorted(root.glob(pattern)):
            if not f.is_file() or "__pycache__" in f.parts:
                continue
            out[str(f.relative_to(root))] = _digest(f)
    return out


def _run(args: list[str], timeout: int = 1800) -> tuple[int, str]:
    res = subprocess.run([sys.executable, "-m", "stop_guessing.cli.main", *args],
                         capture_output=True, cwd=str(REPO), timeout=timeout)
    return res.returncode, (res.stdout + res.stderr).decode("utf-8", "replace")


def build(root: Path = REPO) -> dict:
    """Assemble the bundle from what the tools actually report, not from what we would like."""
    sys.path.insert(0, str(root / "scripts"))
    from audit_verify import BEHAVIOURAL, head_commit, run_all

    rc, attest_raw = _run(["attest", "--self", "--json"])
    try:
        attest = json.loads(attest_raw)
    except ValueError:
        attest = {"error": "attest --self did not produce JSON", "exit_code": rc,
                  "output_tail": attest_raw[-800:]}

    findings = run_all()
    absent = [f for f in findings if f["status"] == "ABSENT"]
    axes = attest.get("assurance") or {}

    return {
        "_type": "https://stop-guessing.dev/ReleaseBundle/v1",
        "commit": head_commit(),
        "version": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "subject": subject(root),
        "attestation": {
            "claims_proven": f"{attest.get('proven')}/{attest.get('total')}",
            "chain_intact": attest.get("chain_intact"),
            "chain_keyed": attest.get("chain_keyed"),
            "self_attestation_complete": attest.get("self_attestation_complete"),
            "release_assured": attest.get("release_assured"),
            "assurance_axes": axes,
        },
        "audit": {
            "source": "STOP-GUESSING_HARDENING_AUDIT_PASSOFF_2026-08-04 and ROUND2 2026-08-05",
            "total": len(findings),
            "absent": len(absent),
            "present": sum(1 for f in findings if f["status"] == "PRESENT"),
            "dynamic": sum(1 for f in findings if f["status"] == "DYNAMIC"),
            "absent_behavioural": sum(1 for f in absent if f["confidence"] == BEHAVIOURAL),
            "absent_structural_only": sum(1 for f in absent if f["confidence"] != BEHAVIOURAL),
        },
        "what_this_does_not_establish": [
            "independent reproduction — `independently_reproduced` is false and cannot be set by "
            "the party that produced this bundle. That is the point of publishing it.",
            "that the proof ledger verifies: the chain is keyed, and a verifier without the key "
            "gets chain shape only. The keyid is recorded so a holder can check; a stranger "
            "cannot, and this bundle does not pretend otherwise.",
            "correctness of the software. The subject digests establish WHICH bytes were "
            "attested, not that those bytes are right.",
            f"the {sum(1 for f in absent if f['confidence'] != BEHAVIOURAL)} audit findings whose "
            "ABSENT rests on a structural predicate — a regression checklist, not evidence the "
            "original risk is gone.",
        ],
        "reproduce": [
            "git clone https://github.com/mEllergrace/stop-guessing && cd stop-guessing",
            "git checkout <commit above>",
            "scripts/release_bundle.py --verify   # recomputes every subject digest",
            "python -m pytest -q                  # the suite, no key required",
            "scripts/audit_verify.py              # finding status, no key required",
            "stop-guessing attest --self          # REQUIRES the chain key; without it, exit 2",
        ],
    }


def verify(bundle_path: Path = BUNDLE, root: Path = REPO) -> dict:
    """Recompute what a third party can recompute, and report every disagreement."""
    doc = json.loads(bundle_path.read_text(encoding="utf-8"))
    recorded = doc.get("subject") or {}
    now = subject(root)

    changed = sorted(k for k in recorded if k in now and recorded[k] != now[k])
    missing = sorted(k for k in recorded if k not in now)
    added = sorted(k for k in now if k not in recorded)

    return {
        "commit": doc.get("commit"),
        "files_checked": len(recorded),
        "changed": changed,
        "missing": missing,
        "added": added,
        "subject_matches": not (changed or missing or added),
        # Reported, never inferred: a matching subject says the bytes are the ones attested. It
        # says nothing about whether the attestation was correct.
        "note": ("A matching subject establishes that these are the bytes the recorded attestation "
                 "was made against. It does not establish that the attestation is right, and it "
                 "is not independent reproduction — that requires running the suite and the "
                 "attestation yourself and comparing verdicts."),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--path", default=str(BUNDLE))
    args = ap.parse_args(argv)
    path = Path(args.path)

    if args.verify:
        if not path.is_file():
            print(f"no bundle at {path}; build one first")
            return 2
        result = verify(path)
        print(f"bundle    : {path}")
        print(f"commit    : {result['commit']}")
        print(f"files     : {result['files_checked']} checked")
        for kind in ("changed", "missing", "added"):
            for f in result[kind][:10]:
                print(f"  {kind.upper():<8} {f}")
            if len(result[kind]) > 10:
                print(f"  … and {len(result[kind]) - 10} more {kind}")
        print(f"\nSUBJECT {'MATCHES' if result['subject_matches'] else 'DIFFERS'}")
        print(f"\n{result['note']}")
        return 0 if result["subject_matches"] else 1

    doc = build()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path}")
    print(f"  commit  : {doc['commit']}")
    print(f"  subject : {len(doc['subject'])} files")
    print(f"  claims  : {doc['attestation']['claims_proven']}")
    print("  axes    : " + ", ".join(
        f"{k}={v}" for k, v in (doc["attestation"]["assurance_axes"] or {}).items()
        if isinstance(v, bool)))
    print(f"  audit   : {doc['audit']['absent']} absent "
          f"({doc['audit']['absent_behavioural']} behavioural, "
          f"{doc['audit']['absent_structural_only']} structural only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
