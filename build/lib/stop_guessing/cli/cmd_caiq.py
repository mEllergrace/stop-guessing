"""`stop-guessing caiq …` — inspect, derive from proofs, fill, verify."""

from __future__ import annotations

from stop_guessing.attest.keys import from_env, from_keyfile
from stop_guessing.version import repo_root

#: Fixes #26. The default was hard-coded to one machine's path, so every `caiq` subcommand was
#: unusable elsewhere without --template — and it is exactly what repo-hygiene's hardcoded-paths
#: check exists to flag. Resolution order, most portable first; refusal names the whole search
#: path rather than silently falling back to a developer's home directory.
TEMPLATE_SEARCH = (
    "$STOP_GUESSING_CAIQ_TEMPLATE",
    "docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx",
    "~/Software/rockin-robin/docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx",
    "~/.claude/plugins/cache/rich-text/rich-text/*/skills/rich-text/docs/ai-caiq/reference/AI_CAIQv1.1.0.xlsx",
)


def resolve_template(explicit: str | None = None) -> str:
    """First readable candidate wins. Raises with the search path if none is found."""
    import glob
    import os

    if explicit:
        return explicit
    tried = []
    for cand in TEMPLATE_SEARCH:
        if cand.startswith("$"):
            v = os.environ.get(cand[1:])
            if not v:
                tried.append(f"{cand} (unset)")
                continue
            cand = v
        expanded = os.path.expanduser(cand)
        if not os.path.isabs(expanded):
            expanded = str(repo_root() / expanded)
        hits = sorted(glob.glob(expanded))
        tried.append(expanded)
        if hits:
            return hits[-1]
    raise FileNotFoundError(
        "no AI-CAIQ template found. It is a COPY-ONLY CSA artifact, gitignored upstream and not "
        "recoverable from GitHub, so it is never shipped here. Pass --template or set "
        "$STOP_GUESSING_CAIQ_TEMPLATE. Searched:\n  " + "\n  ".join(tried)
    )


TEMPLATE_DEFAULT = None
CAIQ_DIR = repo_root() / "docs" / "ai-caiq"
ANSWERS = CAIQ_DIR / "stop-guessing.yaml"
WORKBOOK = CAIQ_DIR / "AI-CAIQ-stop-guessing-v1.1.0.xlsx"


def _key(args):
    if getattr(args, "keyfile", None):
        got = from_keyfile(args.keyfile)
        if got:
            return got[0]
    got = from_env()
    return got[0] if got else None


def cmd_inspect(args) -> int:
    args.template = resolve_template(args.template)
    from stop_guessing.caiq.workbook import inspect

    ins = inspect(args.template)
    print(f"path       : {ins.path}")
    print(f"A1         : {ins.a1_raw}")
    print(f"spec       : {ins.specification_name} {ins.specification_version}")
    print(f"caiq       : {ins.caiq_version}")
    print(f"data sheet : {ins.data_sheet}")
    print(f"dimensions : {ins.dimensions}")
    print(f"digest     : {ins.digest}")
    if ins.ok:
        print("PASS: matches the pinned expectation")
        return 0
    print("DRIFT:")
    for f in ins.findings:
        print(f"  - {f}")
    return 1


def cmd_derive(args) -> int:
    """Compute answers FROM the proofs. Never the other way round."""
    import yaml

    from stop_guessing.caiq.answers import derive, to_yaml_doc

    key = _key(args)
    if key is None:
        print("REFUSED: no chain key — proofs cannot be verified, so answers cannot be derived.")
        return 2
    answers, result = derive(key)
    if not result["chain_intact"]:
        print(f"REFUSED: the proof ledger's chain is broken ({result['chain_reason']}). "
              "Answers derived from an unverifiable ledger are not answers.")
        return 2
    doc = to_yaml_doc(answers, result)
    CAIQ_DIR.mkdir(parents=True, exist_ok=True)
    ANSWERS.write_text(yaml.safe_dump(doc, sort_keys=False, width=100, allow_unicode=True),
                       encoding="utf-8")
    print(f"derived {len(answers)} control answer(s) from {result['proven']}/{result['total']} "
          f"proven claims")
    for a in answers:
        print(f"  {a.control:<10} {a.answer:<4} {len(a.evidence)} proof(s)  {','.join(a.claims)}")
    print(f"-> {ANSWERS.relative_to(repo_root())}")
    return 0


def cmd_fill(args) -> int:
    args.template = resolve_template(args.template)
    import yaml

    from stop_guessing.caiq.fill import FillRefused, fill, verify_with_rich_text

    if not ANSWERS.is_file():
        print(f"REFUSED: no derived answers at {ANSWERS}. Run `caiq derive` first — the workbook "
              "is a rendering of the ledger, not an input to it.")
        return 2
    doc = yaml.safe_load(ANSWERS.read_text(encoding="utf-8"))
    # doc["answers"] holds ONLY published AICM v1.1.0 controls; the proposed agentic ones live
    # in doc["proposed_agentic_controls"] and are deliberately never written into CSA's workbook.
    answers = {a["control"]: {"answer": a["answer"], "ssrm": a.get("ssrm"),
                              "implementation": a["implementation"]}
               for a in doc["answers"]}
    for a in answers.values():
        if a["answer"] == "NA":
            a["ssrm"] = None
    try:
        res = fill(args.template, answers, WORKBOOK)
    except FillRefused as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"filled {res.controls_answered} controls across {res.rows_written} question rows")
    print(f"template untouched: {res.template_untouched} ({res.template_digest_before[:16]}…)")
    ok, detail = verify_with_rich_text(args.template, WORKBOOK)
    print(f"rich-text verifier: {'PASS' if ok else 'FAIL'} — {detail.splitlines()[-1]}")
    print(f"-> {WORKBOOK.relative_to(repo_root())}")
    return 0 if ok else 1


def cmd_evidence_check(args) -> int:
    import yaml

    from stop_guessing.prove import runner

    if not ANSWERS.is_file():
        print(f"no answers at {ANSWERS}")
        return 1
    key = _key(args)
    if key is None:
        # Exit 2, not 1. Without the key nothing resolves, and reporting that as STALE would
        # claim a finding that was never made — the same distinction `page check` draws.
        print("SKIPPED: no chain key, so no evidence ref can be verified. This is not the same "
              "as stale evidence, and must not be reported as it.")
        return 2
    doc = yaml.safe_load(ANSWERS.read_text(encoding="utf-8"))
    result = runner.check(key, runner.DEFAULT_LEDGER)
    live = {ref for row in result["rows"] for ref in row["live"]}
    bad = []
    for a in doc["answers"]:
        for ev in a.get("evidence") or []:
            if ev["ref"] not in live:
                bad.append((a["control"], ev["ref"]))
    total = sum(len(a.get("evidence") or []) for a in doc["answers"])
    print(f"chain intact: {result['chain_intact']}  keyed: {result['chain_keyed']}")
    print(f"evidence refs: {total}, resolving: {total - len(bad)}")
    for ctrl, ref in bad:
        print(f"  STALE {ctrl} -> {ref}")
    if bad or not result["chain_intact"]:
        print("Stale evidence demotes the answer to unassessed — never silently in the workbook.")
        return 1
    print("PASS: every evidence ref resolves to a verified ledger record")
    return 0


def register(sub) -> None:
    p = sub.add_parser("caiq", help="the carried AI-CAIQ")
    s = p.add_subparsers(dest="caiq_cmd", required=True)

    def common(sp):
        sp.add_argument("--template", default=None,
                        help="path to CSA's blank AI-CAIQ; resolved if omitted")
        sp.add_argument("--keyfile")
        return sp

    common(s.add_parser("inspect", help="parse cell A1 and check it against the pinned expectation")
           ).set_defaults(fn=cmd_inspect)
    common(s.add_parser("derive", help="compute answers FROM the proofs")).set_defaults(fn=cmd_derive)
    common(s.add_parser("fill", help="render the workbook from the derived answers")
           ).set_defaults(fn=cmd_fill)
    common(s.add_parser("evidence", help="re-resolve every evidence ref")
           ).set_defaults(fn=cmd_evidence_check)
