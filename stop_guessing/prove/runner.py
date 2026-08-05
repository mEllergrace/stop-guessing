"""Run proof procedures, record them in our own ledger, and write the record ids back.

This is the only writer of `proofs:` in `docs/claims.yaml`. The direction of causation is the
whole point: the evidence is produced first, in a ledger the agent cannot forge, and the artifact
is derived from it. Reversing that — filling the artifact and then hunting for evidence — is the
failure this toolchain exists to make impossible.

A proof reference is only honoured if its ledger record still verifies under the chain key. A
record id in `claims.yaml` whose chain has since broken is not a proof; `claims check` reports it
as broken rather than counting it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from stop_guessing.ledger.chain import ChainKey
from stop_guessing.ledger.sink import load, record
from stop_guessing.prove import witness as _witness
from stop_guessing.prove.registry import Procedure, ProofResult, all_procedures, get
from stop_guessing.version import __version__, repo_root

CLAIMS = repo_root() / "docs" / "claims.yaml"
DEFAULT_LEDGER = repo_root() / ".stop-guessing" / "proofs.jsonl"

PROOF_REF_PREFIX = "sg"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def proof_ref(entry: dict) -> str:
    """A stable, checkable reference to one ledger record: ``sg:<seq>:<hash16>``."""
    return f"{PROOF_REF_PREFIX}:{entry['seq']}:{entry['hash'][:16]}"


def load_claims() -> dict:
    import yaml

    return yaml.safe_load(CLAIMS.read_text(encoding="utf-8"))


def save_claims(doc: dict) -> None:
    """Write claims.yaml, stamping the current version into meta.

    meta.version drifted to 0.1.0 while VERSION moved to 0.2.0, caught by
    test_claims_meta_version_agrees. Anything a human has to remember to update in two places
    eventually disagrees, so the writer stamps it.
    """
    import yaml

    doc.setdefault("meta", {})["version"] = __version__

    header = (
        "# STOP-GUESSING — application claims\n"
        "#\n"
        "# `proofs:` is written ONLY by `stop-guessing prove`. Never edit it by hand: a record id\n"
        "# a human could type proves only that a human typed. Each proof is a record id in this\n"
        "# toolchain's own keyed ledger, and `stop-guessing claims check` re-verifies the chain\n"
        "# covering it before counting it.\n"
        "#\n"
        "# See IMPLEMENTATION_PLAN.md §2.1 (definition of done) and §14 M10.\n\n"
    )
    body = yaml.safe_dump(doc, sort_keys=False, width=100, allow_unicode=True)
    CLAIMS.write_text(header + body, encoding="utf-8")


@dataclass
class RunOutcome:
    claim_id: str
    passed: bool
    ref: str | None
    observations: list[str]
    detail: str


def evidence_subject() -> dict:
    """What a proof was actually exercised AGAINST — the thing it is current for.

    #36 (SG-HARD-003). A proof pinned `inspect.getsource()` of the decorated procedure and nothing
    else, so production behaviour could change materially while the proof stayed "current": edit a
    policy rule, a classification rule or an implementation helper, leave the proof function
    untouched, and the claim still read as proven. The procedure is the *instrument*; it is not
    the subject.

    Bound here: the policy set, the classification rules, and the interpreter. Deliberately NOT the
    whole source tree — a digest over every file would invalidate every proof on a comment change,
    which trains people to stop re-proving. These are the inputs that change what the system
    DECIDES.
    """
    from stop_guessing.artifacts.digest import bytes_digest, file_digest
    from stop_guessing.version import policy_dir, rules_dir

    def _tree(d) -> str:
        parts = []
        for f in sorted(Path(d).rglob("*.yaml")) if Path(d).is_dir() else []:
            parts.append(f"{f.name}:{file_digest(f)}")
        return bytes_digest("|".join(parts).encode())[:32] if parts else ""

    import sys as _sys

    return {
        "policy_set_digest": _tree(policy_dir()),
        "rules_digest": _tree(rules_dir()),
        "python": f"{_sys.version_info.major}.{_sys.version_info.minor}",
        "version": __version__,
    }


def subject_drift(recorded: dict | None) -> list[str]:
    """Which parts of the evidence subject have moved since the proof was recorded."""
    if not recorded:
        return []          # proofs predating the subject block are handled by the witness rules
    now = evidence_subject()
    out = []
    for k, was in recorded.items():
        is_ = now.get(k)
        if was and is_ and was != is_:
            out.append(f"{k} changed since this proof ({was[:12]} -> {str(is_)[:12]})")
    return out


def run_one(
    claim_id: str,
    key: ChainKey | None,
    ledger: Path = DEFAULT_LEDGER,
    *,
    write_back: bool = True,
) -> RunOutcome:
    """Execute one claim's procedure and record what it observed."""
    proc: Procedure | None = get(claim_id)
    if proc is None:
        return RunOutcome(claim_id, False, None, [], "no procedure registered")

    # Run under instrumentation (#31): a procedure that executes nothing and returns
    # passed=True is not a proof, and all 21 could be mutated that way undetected.
    try:
        result, wit = _witness.observe(proc.fn)
        assert isinstance(result, ProofResult)
    except Exception as exc:  # noqa: BLE001 - a crashing procedure is a finding, not a stack trace
        result = ProofResult(passed=False, observations=[f"procedure raised: {exc!r}"])
        wit = _witness.Witness(unavailable=f"procedure raised {type(exc).__name__}")

    wit_findings = _witness.check(
        wit.to_dict(), _must_touch(claim_id),
        mode=_witness_mode(claim_id), evidence=result.evidence,
    )
    if wit_findings and result.passed:
        result.passed = False
        result.observations.extend(f"WITNESS: {f}" for f in wit_findings)

    entry = record(
        ledger,
        {
            "op": "proof.run",
            "actor": f"stop-guessing/{__version__}",
            "at": _now(),
            "severity": "info" if result.passed else "critical",
            "claim": claim_id,
            "proof_kind": proc.kind,
            "procedure": proc.fn.__name__,
            "procedure_digest": proc.source_digest(),
            "evidence_subject": evidence_subject(),
            "witness": wit.to_dict(),
            "judge": _judge_panel(claim_id, proc, wit, result).to_dict(),
            "summary": proc.summary,
            "passed": result.passed,
            "observations": result.observations,
            "evidence": result.evidence,
            "detail": result.detail,
        },
        key,
    )
    ref = proof_ref(entry)

    if write_back and result.passed:
        doc = load_claims()
        for c in doc["claims"]:
            if c["id"] == claim_id:
                # One current proof per claim. The ledger keeps every run; claims.yaml cites
                # the one that is current, so the artifact derived from it is stable when the
                # evidence is stable.
                c["proofs"] = [ref]
                c["last_proved"] = entry["at"]
                break
        save_claims(doc)

    return RunOutcome(claim_id, result.passed, ref, result.observations, result.detail)


def _judge_panel(claim_id: str, proc, wit, result):
    """Judge the procedure's adequacy. Disapproval is DEFERRED, never blocking (#29).

    A mechanical lens is qualified to make a human look, not to void a proof. Blocking on a
    heuristic would either be ignored or would train people to weaken the heuristic.
    """
    from stop_guessing.prove import judge as _judge

    return _judge.judge(claim_id, proc.fn, proc.kind,
                        {"witness": wit.to_dict(), "evidence": result.evidence})


def _witness_mode(claim_id: str) -> str:
    """`subprocess` for proofs that drive the packaged CLI or a real hook in a child process."""
    try:
        for c in load_claims()["claims"]:
            if c["id"] == claim_id:
                return c.get("witness_mode") or "in-process"
    except Exception:  # noqa: BLE001
        return "in-process"
    return "in-process"


def _must_touch(claim_id: str) -> list[str]:
    """Modules a genuine proof of this claim has to enter, from claims.yaml."""
    try:
        for c in load_claims()["claims"]:
            if c["id"] == claim_id:
                return list(c.get("must_touch") or [])
    except Exception:  # noqa: BLE001
        return []
    return []


def run_all(key: ChainKey | None, ledger: Path = DEFAULT_LEDGER,
            *, only: list[str] | None = None) -> list[RunOutcome]:
    procs = all_procedures()
    ids = only or sorted(procs)
    return [run_one(cid, key, ledger) for cid in ids if cid in procs]


def registered_hook_events(root: Path | None = None) -> set[str]:
    """The hook events the shipped plugin actually registers."""
    import json as _json

    p = (root or repo_root()) / ".claude-plugin" / "plugins" / "stop-guessing" / "hooks" / "hooks.json"
    try:
        doc = _json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return set((doc.get("hooks") or doc).keys())


def _surface_findings(claim: dict) -> tuple[list[str], list[str]]:
    """Check a claim's declared `surface:` against reality. Returns (findings, unvalidated).

    #34 (SG-HARD-001). The gate validated the chain, the record, the procedure digest and an
    execution witness, and never once looked at what the claim said it exercised. Three claims
    declared `hook:PreCompact`, `hook:Stop` and `hook:SessionStart` while the plugin registered
    neither — their procedures called the underlying library directly and passed. That is the exact
    defect the external review named: *a primitive can work while the installed system never
    invokes it.*

    Only `hook:` is decidable from the tree today, so only `hook:` blocks. The other kinds are
    returned as `unvalidated` rather than silently treated as satisfied — a surface nobody checked
    must read as unchecked, not as passed, which is the same rule this project applies to
    `known_gaps`.
    """
    findings: list[str] = []
    unvalidated: list[str] = []
    registered = registered_hook_events()
    for surface in claim.get("surface") or []:
        s = str(surface)
        kind, _, rest = s.partition(":")
        if kind == "hook":
            if rest not in registered:
                findings.append(
                    f"declares {s} but no {rest} hook is registered in the plugin "
                    f"(registered: {', '.join(sorted(registered)) or 'none'})"
                )
        else:
            unvalidated.append(s)
    return findings, unvalidated


def check(key: ChainKey | None, ledger: Path = DEFAULT_LEDGER) -> dict:
    """The release gate. A claim with no surviving proof is FAILED, not unassessed."""
    doc = load_claims()
    procs = all_procedures()
    loaded = load(ledger, key)
    by_ref = {proof_ref(e): e for e in loaded.entries if e.get("op") == "proof.run"}

    # #37 (SG-HARD-004): an intact PREFIX is not an intact ledger. load() preserves everything up
    # to a torn or malformed record and reports `truncated` separately; this read only
    # `chain.intact`, so appending one partial line after the final proof left every earlier proof
    # live and still produced a full verdict — while the sink itself refused to write another
    # record. The gate now agrees with the sink about what a usable ledger is.
    # #64 adds corruption alongside truncation: an unparseable middle line or invalid UTF-8 is
    # damage a crash cannot explain, and must invalidate at least as strongly as a torn tail.
    chain_ok = loaded.usable

    # Evidence is CURRENT, not cumulative. Every prove run appended another ref, so a control
    # ended up citing 60 records where 59 were superseded re-runs of the same procedure — and the
    # workbook changed on every loop even when nothing about the tool had, which made the digest
    # binding fragile by construction. The latest surviving proof per claim is the evidence; the
    # earlier ones stay in the ledger as history and are reported as superseded, not as dead.
    seq_of = {}
    for e in loaded.entries:
        if e.get("op") == "proof.run":
            seq_of[proof_ref(e)] = e.get("seq", -1)

    rows = []
    for c in doc["claims"]:
        refs = list(c.get("proofs") or [])
        live, dead, superseded = [], [], []
        for ref in refs:
            e = by_ref.get(ref)
            if e is None:
                dead.append(f"{ref} not found in the ledger")
            elif not e.get("passed"):
                dead.append(f"{ref} records a FAILED run")
            elif e.get("claim") != c["id"]:
                dead.append(f"{ref} was recorded against {e.get('claim')}")
            else:
                proc = procs.get(c["id"])
                drift = subject_drift(e.get("evidence_subject"))
                if proc and e.get("procedure_digest") not in (proc.source_digest(), "unavailable"):
                    dead.append(f"{ref} was produced by a since-modified procedure")
                elif drift:
                    # #36: the procedure is unchanged but what it exercised is not.
                    dead.append(f"{ref}: {drift[0]}")
                else:
                    wf = _witness.check(
                        e.get("witness"), _must_touch(c["id"]),
                        mode=_witness_mode(c["id"]), evidence=e.get("evidence"),
                    )
                    if wf:
                        dead.append(f"{ref}: {wf[0]}")
                    else:
                        live.append(ref)

        # Keep only the most recent surviving proof. Older ones are history, not extra assurance.
        if len(live) > 1:
            live.sort(key=lambda r: seq_of.get(r, -1))
            superseded = live[:-1]
            live = live[-1:]
        proc = procs.get(c["id"])
        has_procedure = c["id"] in procs
        # #35 (SG-HARD-002): this was `proc is None or ...`, so a claim whose procedure had been
        # deleted evaluated kind_ok=True, kept its historical record live (there was no current
        # source to compare the digest against), and reported PROVEN with has_procedure=False
        # sitting unread beside it. A claim nobody can re-run is not a proven claim.
        kind_ok = has_procedure and proc.kind == c.get("proof_kind")
        surface_findings, unvalidated = _surface_findings(c)
        rows.append({
            "id": c["id"],
            "milestone": c.get("milestone"),
            "proof_kind": c.get("proof_kind"),
            "has_procedure": has_procedure,
            "kind_matches": kind_ok,
            "live": live,
            "dead": dead,
            "superseded": superseded,
            "surface_findings": surface_findings,
            "unvalidated_surfaces": unvalidated,
            "proven": (bool(live) and chain_ok and kind_ok and has_procedure
                       and not surface_findings),
        })

    proven = [r for r in rows if r["proven"]]
    return {
        # `chain_intact` is the USABLE verdict (intact and not truncated); the two inputs are
        # reported separately so a truncation can never be mistaken for a hash break, or hidden.
        "chain_intact": chain_ok,
        "chain_verified": loaded.chain.intact,
        "chain_truncated": loaded.truncated,
        "chain_corrupt": loaded.corrupt,
        "chain_malformed_at": loaded.malformed_at,
        "chain_decode_error_at": loaded.decode_error_at,
        "chain_reason": (
            loaded.chain.reason if not loaded.chain.intact
            else f"line {loaded.malformed_at} is unparseable and is not the final line — "
                 "corruption, not an interrupted write" if loaded.malformed_at
            else f"line {loaded.decode_error_at} is not valid UTF-8 — corruption"
                 if loaded.decode_error_at
            else "the final record is partial; the ledger is a prefix, not a ledger"
                 if loaded.truncated else None),
        "chain_keyed": loaded.chain.verified_keyed,
        "ledger": str(ledger),
        "total": len(rows),
        "proven": len(proven),
        "unproven": [r["id"] for r in rows if not r["proven"]],
        "rows": rows,
        "ok": len(proven) == len(rows) and chain_ok,
    }


def attest_self(
    key: ChainKey | None,
    ledger: Path = DEFAULT_LEDGER,
    caiq_dir: Path | None = None,
) -> dict:
    """The one-line answer to the goal: claims -> proofs -> controls, plus the AI-CAIQ state.

    ``caiq_dir`` is injectable so this is testable hermetically. It was not, and a test asserting
    "the goal is not met before the workbook exists" started passing for the wrong reason the
    moment the real workbook was generated — a test reading production state is not a test.
    """
    result = check(key, ledger)
    doc = load_claims()

    controls: dict[str, list[str]] = {}
    for c in doc["claims"]:
        row = next(r for r in result["rows"] if r["id"] == c["id"])
        if row["proven"]:
            for ctrl in c.get("aicm") or []:
                controls.setdefault(ctrl, []).append(c["id"])

    cdir = caiq_dir or (repo_root() / "docs" / "ai-caiq")
    filled = sorted(p.name for p in cdir.glob("AI-CAIQ-*.xlsx")) if cdir.is_dir() else []
    answers = cdir / "stop-guessing.yaml"

    # #21: file existence WAS the entire CAIQ leg of the verdict. It did not check that the
    # workbook is the one the proof was recorded against, that the answers declare themselves
    # derived, or that their evidence still resolves. "A file named AI-CAIQ-*.xlsx exists" is not
    # evidence, and a hand-edited workbook kept reporting GOAL MET.
    caiq_findings = []
    workbook_bound = False
    if filled and answers.is_file():
        from stop_guessing.artifacts.digest import file_digest

        proof = None
        for e in load(ledger, key).entries:
            if e.get("op") == "proof.run" and e.get("claim") == "CLAIM-21" and e.get("passed"):
                proof = e
        if proof is None:
            caiq_findings.append("no passing CLAIM-21 proof, so no workbook digest is bound")
        else:
            pinned = (proof.get("evidence") or {}).get("workbook_digest")
            actual = file_digest(cdir / filled[-1])
            if not pinned:
                caiq_findings.append("the CLAIM-21 proof pinned no workbook digest")
            elif pinned != actual:
                caiq_findings.append(
                    "the workbook changed since it was proven (proof pinned "
                    + pinned[:16] + ", on disk " + str(actual)[:16]
                    + ") - edited outside the pipeline, or re-derived without re-proving"
                )
            else:
                workbook_bound = True
        try:
            import yaml as _yaml

            adoc = _yaml.safe_load(answers.read_text(encoding="utf-8"))
            note = (adoc.get("meta") or {}).get("note") or ""
            if "DERIVED from proofs" not in note:
                caiq_findings.append("the answers file does not declare itself derived")
            live = {r for row in result["rows"] for r in row["live"]}
            stale = [ev.get("ref") for a in (adoc.get("answers") or [])
                     for ev in (a.get("evidence") or []) if ev.get("ref") not in live]
            if stale:
                caiq_findings.append(
                    str(len(stale)) + " evidence ref(s) no longer resolve to a live proof, e.g. "
                    + str(stale[0])
                )
        except Exception as exc:  # noqa: BLE001
            caiq_findings.append("the answers file could not be read: " + str(exc))

    result["aicm_controls_evidenced"] = dict(sorted(controls.items()))
    result["caiq"] = {
        "answers_present": answers.is_file(),
        "filled_workbooks": filled,
        "workbook_digest_bound": workbook_bound,
        "findings": caiq_findings,
        "filled_from_proofs": (bool(filled) and answers.is_file() and workbook_bound
                               and not caiq_findings),
    }
    from stop_guessing.prove.judge import Panel, Verdict

    panels = []
    for e in load(ledger, key).entries:
        if e.get("op") == "proof.run" and e.get("passed") and e.get("judge"):
            j = e["judge"]
            panels.append(Panel(j["claim"], [Verdict(**v) for v in j["verdicts"]]))
    latest = {}
    for pn in panels:
        latest[pn.claim_id] = pn
    from stop_guessing.prove.judge import summarise as _sum

    result["judge"] = _sum(list(latest.values()))

    # Deliberately NOT part of goal_met. Deferred means recorded and surfaced, not blocking.
    result["goal_met"] = bool(
        result["ok"] and result["chain_keyed"] and result["caiq"]["filled_from_proofs"]
    )

    # #77 (SG-HARD-044). One boolean collapsed four different questions, so a headline could read
    # "met" while 21 independence objections and a pile of missing-control findings sat recorded
    # and unread. The judge must NOT gain a veto — a mechanical lens is qualified to make a human
    # look, not to void a proof, and giving it a veto would only teach people to weaken the lens.
    # So the axes are reported separately instead of one being folded into another.
    judge = result.get("judge") or {}
    unvalidated = sorted({s for r in result["rows"] for s in (r.get("unvalidated_surfaces") or [])})
    result["assurance"] = {
        "executed": bool(result["ok"]),
        "chain_verified": bool(result["chain_keyed"] and result["chain_intact"]),
        "surface_validated": not unvalidated,
        "unvalidated_surfaces": unvalidated,
        "control_backed": not judge.get("deferred_disapprovals"),
        "deferred_disapprovals": judge.get("deferred_disapprovals", 0),
        "independently_reproduced": False,
        "note": (
            "Four axes, deliberately not collapsed. `executed` says the procedures ran and were "
            "witnessed. `control_backed` is FALSE while any judge lens has a deferred objection — "
            "recorded, never blocking. `independently_reproduced` is hardcoded False: nothing in "
            "this repository can set it, because self-attestation cannot establish it. Only a "
            "third party reproducing the release bundle can, and until then saying so is the "
            "honest answer."
        ),
    }
    return result


def summarise(result: dict) -> str:
    lines = [json.dumps({"proven": result["proven"], "total": result["total"]})]
    return "\n".join(lines)
