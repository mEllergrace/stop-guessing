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


#: Claim fields that define WHAT is being asserted. A change to any of them changes the claim, so
#: a proof issued against the old text must stop counting. R2-001.
CLAIM_DEFINITION_FIELDS = ("id", "statement", "surface", "proof_kind", "aicm", "must_touch",
                           "milestone", "witness_mode")


def claim_definition_digest(claim: dict) -> str:
    """Digest the claim's DEFINITION, canonically.

    R2-001. A proof record carried the claim ID, procedure digest, evidence subject, witness and
    judge result — and nothing that pinned the claim TEXT. So a statement could be retracted,
    broadened, narrowed or reformed after its proof was issued and the old proof stayed live. The
    system proved "procedure X passed for claim ID Y", not "the assertion now displayed was
    established". That is precisely the gap between an internally consistent record and a
    defensible one, and it was live for CLAIM-09, 12, 18 and 20, whose text changed after proof.

    `proofs` and `last_proved` are excluded: they are the RESULT of proving and would make the
    digest change every time a proof was recorded, which is the same recursion CLAIM-21 had.
    """
    import json as _json

    material = {k: claim.get(k) for k in CLAIM_DEFINITION_FIELDS}
    canon = _json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    from stop_guessing.artifacts.digest import bytes_digest

    return bytes_digest(canon.encode("utf-8"))[:32]


def implementation_manifest(modules: list[str]) -> dict:
    """Digest the production modules a proof actually traversed.

    R2-002. The evidence subject bound the policy tree, the rules tree, the interpreter and the
    package version — but not the bytes of the implementation the procedure exercised. `must_touch`
    proves a module was ENTERED; it does not pin what was in it. A helper, a daemon, a lifecycle
    hook, a sandbox or the replay logic could change while the procedure, policy, Python version
    and VERSION all stayed put, and the stale proof kept counting. That is the round-1 staleness
    defect in reduced form, and round 2 was right that it was still material.

    Only `stop_guessing.*` modules are bound: third-party and stdlib bytes are the interpreter's
    business and pinning them would invalidate every proof on an unrelated upgrade.
    """
    from stop_guessing.artifacts.digest import file_digest

    out: dict[str, str] = {}
    for name in sorted(modules or []):
        if not name.startswith("stop_guessing"):
            continue
        rel = Path(*name.split(".")).with_suffix(".py")
        for base in (repo_root(), Path(__file__).resolve().parent.parent.parent):
            f = base / rel
            if f.is_file():
                out[name] = (file_digest(f) or "")[:16]
                break
    return out


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


def _claim_definition_digest_for(claim_id: str) -> str | None:
    """The definition digest for one claim id, or None when the claim cannot be read."""
    try:
        for c in load_claims()["claims"]:
            if c["id"] == claim_id:
                return claim_definition_digest(c)
    except Exception:  # noqa: BLE001 - an unreadable claims file is a finding elsewhere
        return None
    return None


def _implementation_drift(recorded: dict | None) -> list[str]:
    """Which traversed implementation modules have changed since the proof was recorded.

    R2-002. Proofs recorded before this existed carry no manifest; they are handled by the
    procedure-digest and witness rules and are not retroactively invalidated here — a proof cannot
    be blamed for lacking evidence the system did not yet collect. New proofs carry it.
    """
    if not recorded:
        return []
    now = implementation_manifest(list(recorded))
    out = []
    for mod, was in sorted(recorded.items()):
        is_ = now.get(mod)
        if is_ and was and is_ != was:
            out.append(f"{mod} changed after this proof ({was[:12]} -> {is_[:12]})")
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

    # R2-003/R2-039. Each claim's declared `cli:` surfaces are driven as subprocesses against the
    # packaged CLI as part of the proof run, and what actually executed is recorded.
    #
    # The semantics matter and are stated rather than implied: this establishes REACHABILITY — the
    # surface exists, starts, and is not an argparse error. It does NOT establish that the claim's
    # behaviour was observed there; that is what the procedure's own assertions are for, and where
    # a procedure genuinely drives a surface it declares so itself. Conflating the two would be the
    # overclaim this whole audit is about, in a new place.
    # Deliberately AFTER the witness verdict. Running it before meant a VACUOUS procedure —
    # one that executed nothing — still got exercised_surfaces written into its evidence, and
    # the witness reads evidence when judging whether a proof did any work. My own fix made
    # empty proofs look substantive, and tests/test_witness.py caught it on three claims.
    # A surface exercise is a fact about the CLI, never a substitute for the procedure working.
    surfaces_declared = [str(s) for s in (_claim_surfaces(claim_id) or [])]
    try:
        from stop_guessing.prove.procedures import exercise_cli

        declared = [s for s in surfaces_declared if s.startswith("cli:")]
        reachable = exercise_cli(*declared) if declared else []
    except Exception:  # noqa: BLE001 - a surface that cannot be driven stays a finding
        reachable = []

    # The `hook:` half. Six claims declared hooks their procedures never went through, because the
    # procedure called the underlying function directly — the gate said so, correctly, as
    # "registration is not execution". Withdrawing those surfaces would have cleared the finding by
    # shrinking the claim, which is the move scope.py now catches. So the hooks get driven instead:
    # the installed entry point, as its own process, with a realistic payload on stdin.
    try:
        from stop_guessing.prove.procedures import exercise_hooks

        hooks_declared = [s for s in surfaces_declared if s.startswith("hook:")]
        hooks_run = exercise_hooks(*hooks_declared) if hooks_declared else []
    except Exception:  # noqa: BLE001 - a hook that cannot be driven stays a finding
        hooks_run = []

    if (reachable or hooks_run) and result.passed:
        result.evidence = dict(result.evidence or {})
        result.evidence["exercised_surfaces"] = sorted(
            set(result.evidence.get("exercised_surfaces") or []) | set(reachable) | set(hooks_run))
        scope_notes = []
        if reachable:
            scope_notes.append(
                "cli surfaces were executed as subprocesses: this establishes that each is "
                "reachable and runs, NOT that the claim's behaviour was observed through it")
        if hooks_run:
            scope_notes.append(
                "hook surfaces were driven as real subprocesses through the entry point install.sh "
                "registers, with a realistic payload on stdin and the response parsed. That is the "
                "DEPLOYED code path with a SYNTHETIC caller: stronger than 'registered in "
                "settings.json', weaker than 'a live Claude Code session exercised it'. The "
                "difference is stated rather than left to the reader")
        result.evidence["surface_exercise_scope"] = " | ".join(scope_notes)


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
            # R2-001: what was asserted. R2-002: what it was asserted against.
            "claim_definition_digest": _claim_definition_digest_for(claim_id),
            "implementation_manifest": implementation_manifest(sorted(wit.modules)),
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

    # The scope ratchet's input: what this claim asserted at the moment it was proved. Written on
    # every run so a later reduction is measurable against the largest scope ever claimed, not just
    # against yesterday's — shrinking one surface at a time would otherwise never register.
    from stop_guessing.prove import scope as _scope

    # No try/except here on purpose. The first draft swallowed every failure so that "a scope record
    # must never break a proof run" — which is exactly how a control comes to do nothing while
    # reading as present. If the scope cannot be pinned, the ratchet has no baseline and a later
    # reduction is invisible; that must stop the run, not be absorbed by it.
    claim_now = next((c for c in load_claims()["claims"] if c["id"] == claim_id), None)
    if claim_now:
        ev = _scope.scope_event(claim_now)
        ev.update({"actor": f"stop-guessing/{__version__}", "at": _now(), "severity": "info"})
        record(ledger, ev, key)

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


def _claim_surfaces(claim_id: str) -> list[str]:
    try:
        for c in load_claims()["claims"]:
            if c["id"] == claim_id:
                return list(c.get("surface") or [])
    except Exception:  # noqa: BLE001
        return []
    return []


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


def _scope_retractions(entries: list[dict], claim: dict):
    from stop_guessing.prove import scope as _scope

    try:
        return _scope.retractions(entries, claim)
    except Exception:  # noqa: BLE001
        return []


def _exercised_for(claim: dict, by_ref: dict, refs: list[str]) -> set[str]:
    """Surfaces the claim's live proof records actually reported exercising.

    R2-003. A proof declares what it drove by writing `exercised_surfaces` into its evidence; the
    gate reads it here. A procedure that names a hook and never invokes it therefore fails, which
    is the whole point — the previous check asked hooks.json whether the event existed, a question
    about the manifest rather than about the proof.
    """
    out: set[str] = set()
    for ref in refs:
        e = by_ref.get(ref)
        if not e:
            continue
        for s in ((e.get("evidence") or {}).get("exercised_surfaces") or []):
            out.add(str(s))
    return out


#: Surfaces that CANNOT be executed from a proof run on this machine, because driving them requires
#: a live agent session invoking a slash command or loading a plugin. Naming the category is the
#: point: "unchecked" conflated "nobody got round to it" with "not decidable here", and only the
#: first is a to-do. What IS decidable — that the file ships, in the right place, with the right
#: shape, registered where it must be — is checked, and reported as exactly that and nothing more.
LIVE_SESSION_KINDS = ("plugin", "skill", "command")


def structural_findings(surface: str) -> list[str]:
    """What can be established about a plugin/skill/command surface WITHOUT a live session.

    Deliberately narrow. This says the artifact ships and is wired up; it says nothing whatever
    about behaviour. Reporting it as validation of the claim would be the overclaim this whole
    audit is about, in a new place — so it feeds `structurally_validated`, never
    `surface_validated`.
    """
    root = repo_root()
    plugin = root / ".claude-plugin" / "plugins" / "stop-guessing"
    kind, _, rest = str(surface).partition(":")
    out: list[str] = []

    if kind == "command":
        name = rest.lstrip("/")
        # commands/ is what registers a slash command; skills/ alone is written and never loaded
        # (the 2026-07-29 finding). Both install paths must carry it.
        if not (plugin / "commands" / f"{name}.md").is_file():
            out.append(f"{surface}: the plugin ships no commands/{name}.md, so the slash command "
                       "is not registered by the marketplace install path")
        installed_by_script = any(
            "for doc in" in ln and name in ln
            for ln in (root / "install.sh").read_text(encoding="utf-8").splitlines())
        if not installed_by_script:
            out.append(f"{surface}: install.sh does not install {name}.md, so the two supported "
                       "install paths deliver different products")
    elif kind == "skill":
        skill = plugin / "skills" / rest / "SKILL.md"
        if not skill.is_file():
            out.append(f"{surface}: no skills/{rest}/SKILL.md — a flat .md is never loaded")
        elif not skill.read_text(encoding="utf-8").lstrip().startswith("---"):
            out.append(f"{surface}: SKILL.md has no frontmatter, so it will not register")
    elif kind == "plugin":
        manifest = plugin / ".claude-plugin" / "plugin.json"
        if not manifest.is_file():
            out.append(f"{surface}: no .claude-plugin/plugin.json")
        else:
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except ValueError as exc:
                out.append(f"{surface}: plugin.json is not valid JSON ({exc})")
                data = {}
            if data.get("version") != __version__:
                out.append(f"{surface}: plugin.json declares {data.get('version')}, "
                           f"the package is {__version__}")
        if not (plugin / "hooks" / "hooks.json").is_file():
            out.append(f"{surface}: the plugin registers no hooks.json")
    return out


def _surface_findings(claim: dict, exercised=None) -> tuple[list[str], list[str]]:
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
    exercised = set(exercised or ())
    for surface in claim.get("surface") or []:
        s = str(surface)
        kind, _, rest = s.partition(":")
        if kind == "hook":
            if rest not in registered:
                findings.append(
                    f"declares {s} but no {rest} hook is registered in the plugin "
                    f"(registered: {', '.join(sorted(registered)) or 'none'})"
                )
            elif s not in exercised:
                # R2-003. Registration is not exercise. A claim naming `hook:PreCompact` passed
                # because the event appeared in hooks.json, while its procedure called rebuild()
                # in memory and never went near the hook. "The hook exists" and "the proof drove
                # it" are different facts, and only the second supports the claim.
                findings.append(
                    f"declares {s}, which IS registered, but the proof did not exercise it — "
                    "registration is not execution"
                )
        elif kind in ("cli", "daemon"):
            if s not in exercised:
                findings.append(f"declares {s}, which the proof did not execute")
        elif kind in LIVE_SESSION_KINDS:
            # Not executable from a proof run: a slash command needs a live session to invoke it.
            # Still reported as NOT established here — but what IS decidable gets decided, and a
            # structural defect (the plugin shipping no commands/no-noodle.md, say) becomes a
            # blocking finding rather than hiding inside "unchecked".
            findings.extend(structural_findings(s))
            unvalidated.append(s)
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
                # R2-001: the claim text this proof was issued against.
                recorded_def = e.get("claim_definition_digest")
                if recorded_def and recorded_def != claim_definition_digest(c):
                    dead.append(f"{ref}: the claim definition changed after this proof was "
                                "issued (statement, surface, proof_kind, controls or must_touch)")
                    continue
                # R2-002: the implementation bytes it traversed.
                impl_drift = _implementation_drift(e.get("implementation_manifest"))
                if impl_drift:
                    dead.append(f"{ref}: {impl_drift[0]}")
                    continue
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
        surface_findings, unvalidated = _surface_findings(c, _exercised_for(c, by_ref, refs))
        # ISO 27037 §5.4.1 applied to the claim itself: reducing what is asserted alters the
        # evidence subject, so it must carry a written justification. An unjustified reduction is
        # a finding — this is the control that would have caught me narrowing six hook surfaces to
        # make `surface_validated` pass.
        claim_retractions = _scope_retractions(loaded.entries, c)
        unjustified = [r for r in claim_retractions if not r.justified]
        surface_findings = list(surface_findings) + [r.describe() for r in unjustified]
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
            "scope_retractions": [r.to_dict() for r in claim_retractions],
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
    # R2-004. `goal_met` required only the internal claim count, a keyed chain, and a self-derived
    # CAIQ — so it could be true while surface_validated, control_backed AND
    # independently_reproduced were all false. A single word that can be "met" while three named
    # axes say assurance is absent is not a verdict, it is a headline.
    #
    # It is now the narrow thing it actually measured, under a name that says so, and the release
    # verdict requires the axes. `goal_met` is kept as an alias because external callers and the
    # page consume it — but it now tracks the honest value rather than the flattering one.
    result["self_attestation_complete"] = bool(
        result["ok"] and result["chain_keyed"] and result["caiq"]["filled_from_proofs"]
    )

    # #77 (SG-HARD-044). One boolean collapsed four different questions, so a headline could read
    # "met" while 21 independence objections and a pile of missing-control findings sat recorded
    # and unread. The judge must NOT gain a veto — a mechanical lens is qualified to make a human
    # look, not to void a proof, and giving it a veto would only teach people to weaken the lens.
    # So the axes are reported separately instead of one being folded into another.
    judge = result.get("judge") or {}
    unvalidated = sorted({s for r in result["rows"] for s in (r.get("unvalidated_surfaces") or [])})
    all_retractions = [r for row in result["rows"] for r in (row.get("scope_retractions") or [])]
    unjustified_retractions = [r for r in all_retractions if not r.get("justified")]
    result["assurance"] = {
        # Reported beside the verdict on purpose: a reader must be able to see that a claim got
        # smaller in the same breath as the number got better.
        "scope_retractions": len(all_retractions),
        "scope_retractions_unjustified": len(unjustified_retractions),
        "executed": bool(result["ok"]),
        "chain_verified": bool(result["chain_keyed"] and result["chain_intact"]),
        # `surface_validated` stays about EXECUTION. It is false while any declared surface was not
        # driven, including the ones that cannot be driven here — reporting it true because the
        # files are in the right place would be the overclaim this release exists to prevent.
        "surface_validated": not unvalidated,
        "unvalidated_surfaces": unvalidated,
        # Separate axis, separate meaning: these ship, in the right place, with the right shape,
        # registered where they must be. That is a fact about the distribution, not about the
        # claim's behaviour, and it is reported as such. A structural DEFECT is a blocking finding
        # (see structural_findings) — this axis only says none was found.
        "structurally_validated": bool(unvalidated) and not any(
            f for r in result["rows"] for f in (r.get("surface_findings") or [])),
        "surfaces_requiring_live_session": [
            s for s in unvalidated if s.partition(":")[0] in LIVE_SESSION_KINDS],
        # `control_backed` means what it says: every procedure carries a case that must behave the
        # other way. It was defined as "no lens objected AT ALL", which folded in the
        # `independence` lens — and that lens objects on every claim by construction, because the
        # procedures are authored by the party they attest. Self-attestation can never clear it,
        # so under that definition the axis was unreachable and therefore said nothing.
        #
        # Independence has its own axis, `independently_reproduced`, and is still reported there.
        # Collapsing it into this one made two different unknowns look like one failure.
        "control_backed": not judge.get("by_lens", {}).get("control-present"),
        "deferred_disapprovals": judge.get("deferred_disapprovals", 0),
        "deferred_by_lens": judge.get("by_lens", {}),
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
    axes = result["assurance"]
    # A release-assured verdict requires the axes that describe assurance, not just execution.
    result["release_assured"] = bool(
        result["self_attestation_complete"]
        and axes["surface_validated"]
        and axes["control_backed"]
    )
    # Kept for compatibility, and deliberately NOT the flattering value: anything consuming
    # `goal_met` — including the generated page — now reads the assured verdict.
    result["goal_met"] = result["release_assured"]
    return result


def summarise(result: dict) -> str:
    lines = [json.dumps({"proven": result["proven"], "total": result["total"]})]
    return "\n".join(lines)
