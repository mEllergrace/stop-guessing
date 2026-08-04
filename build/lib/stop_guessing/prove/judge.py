"""A judge panel over proof *adequacy*, in rockin-robin's shape.

**Addresses #29.** The execution witness proves a procedure entered the module its claim is about.
It cannot prove the test inside it was strong: a procedure that enters the right module and asserts
something trivial still passes. Nothing self-authored can close that gap, because the same author
wrote the claim and its test — the correlated-reviewer problem `rockin-robin`'s own acceptance
reports disclose: *"2 reviewers share account, image, model — their judgements are correlated, so
treat this consensus as weaker than the vote count suggests."*

So this does what rockin-robin does rather than pretending to independence it does not have:

**Deferred disapproval.** A judge that disapproves records a finding into the keyed ledger and
surfaces it in `attest --self`. It does **not** flip the verdict. A mechanical judge is not
qualified to void a proof — it is qualified to make a human look. Blocking on a heuristic would
either be ignored or would train people to weaken the heuristic, and both are worse than a
recorded, visible dissent. Approval is likewise not evidence of adequacy; it is only the absence of
a mechanical objection.

**Distinct lenses, not repeated votes.** Redundant judges applying one criterion produce a
confident wrong answer. Each lens here asks a different question, and the panel reports its
composition so a reader can see how narrow it is.

**Declared independence.** Every verdict carries `independence`, which currently reads
`same-author` for all of them. That is the honest value and it is recorded in every judgement, so
the panel's weight cannot be overread later.
"""

from __future__ import annotations

import ast
import inspect
import re
from dataclasses import dataclass, field

#: What this panel is, stated so a reader does not infer more.
PANEL_DISCLOSURE = (
    "Mechanical lenses over each procedure's own source, authored by the same party as the "
    "procedures. Independence: NONE. Disapproval is deferred — recorded and surfaced, never "
    "blocking. An approval means no lens objected, which is not evidence of adequacy."
)

APPROVE = "approve"
DEFER = "disapprove-deferred"
ABSTAIN = "abstain"


@dataclass
class Verdict:
    lens: str
    verdict: str
    reason: str
    independence: str = "same-author"

    def to_dict(self) -> dict:
        return {"lens": self.lens, "verdict": self.verdict, "reason": self.reason,
                "independence": self.independence}


@dataclass
class Panel:
    claim_id: str
    verdicts: list[Verdict] = field(default_factory=list)

    @property
    def deferred(self) -> list[Verdict]:
        return [v for v in self.verdicts if v.verdict == DEFER]

    def to_dict(self) -> dict:
        return {
            "claim": self.claim_id,
            "disclosure": PANEL_DISCLOSURE,
            "lenses": len(self.verdicts),
            "approved": sum(1 for v in self.verdicts if v.verdict == APPROVE),
            "deferred_disapprovals": len(self.deferred),
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


# ── the lenses ───────────────────────────────────────────────────────────────


def _source(fn) -> str:
    try:
        return inspect.getsource(fn)
    except (OSError, TypeError):
        return ""


def lens_can_fail(src: str, kind: str, record: dict) -> Verdict:
    """A procedure with no reachable failure path cannot be a proof."""
    fails = len(re.findall(r"\br\.fail\(|return r\.fail\(", src))
    if fails == 0:
        return Verdict("can-fail", DEFER,
                       "the procedure contains no r.fail() path, so it cannot report a false "
                       "claim — it can only agree with itself")
    if fails < 2 and kind in ("adversarial", "negative"):
        return Verdict("can-fail", DEFER,
                       f"only {fails} failure path in a {kind} procedure; an adversarial proof "
                       "usually needs one per attack it claims to catch")
    return Verdict("can-fail", APPROVE, f"{fails} distinct failure paths")


def lens_adversarial_substance(src: str, kind: str, record: dict) -> Verdict:
    """An adversarial or negative proof must actually attempt the thing."""
    if kind not in ("adversarial", "negative"):
        return Verdict("adversarial-substance", ABSTAIN, f"not applicable to a {kind} proof")
    attack = re.findall(
        r"\b(forge|tamper|truncat|mutat|shadow|substitut|rewrit|corrupt|delete|unlink|"
        r"REFUSED|raises|pytest\.raises|except\s+\w*(?:Error|Refused))",
        src, re.IGNORECASE)
    if len(set(a.lower() for a in attack)) < 2:
        return Verdict("adversarial-substance", DEFER,
                       "few adversarial constructs found; a negative proof should attempt the "
                       "failure it claims to detect, not merely observe success")
    return Verdict("adversarial-substance", APPROVE,
                   f"{len(set(a.lower() for a in attack))} distinct adversarial constructs")


def lens_control_present(src: str, kind: str, record: dict) -> Verdict:
    """Does the procedure include a control — a case that must behave the OTHER way?

    Without one, a passing assertion may be passing for an unrelated reason. CLAIM-02's control
    (forging WITH the real key succeeds) is what makes its attack meaningful.
    """
    if re.search(r"\bcontrol\b|CONTROL", src):
        return Verdict("control-present", APPROVE, "an explicit control case is present")
    return Verdict("control-present", DEFER,
                   "no control case found; a passing assertion with nothing to contrast against "
                   "may be passing for a reason unrelated to the claim")


def lens_asserts_on_computed_values(src: str, kind: str, record: dict) -> Verdict:
    """Assertions should compare values the module produced, not restate literals."""
    try:
        tree = ast.parse(src.lstrip())
    except SyntaxError:
        return Verdict("computed-assertions", ABSTAIN, "source could not be parsed")
    calls = sum(1 for n in ast.walk(tree) if isinstance(n, ast.Call))
    compares = sum(1 for n in ast.walk(tree) if isinstance(n, ast.Compare))
    if compares == 0:
        return Verdict("computed-assertions", DEFER, "no comparisons at all")
    if calls < compares:
        return Verdict("computed-assertions", DEFER,
                       f"{compares} comparisons against only {calls} calls — the procedure may be "
                       "comparing literals rather than computed results")
    return Verdict("computed-assertions", APPROVE, f"{calls} calls, {compares} comparisons")


def lens_witness_breadth(src: str, kind: str, record: dict) -> Verdict:
    """Barely clearing the witness floor is a signal worth surfacing."""
    w = record.get("witness") or {}
    if w.get("unavailable"):
        return Verdict("witness-breadth", ABSTAIN, "no witness available")
    calls = w.get("calls") or 0
    if calls < 100:
        return Verdict("witness-breadth", DEFER,
                       f"only {calls} calls into the package; clears the floor but is thin for a "
                       "claim about behaviour")
    return Verdict("witness-breadth", APPROVE, f"{calls} calls, {w.get('module_count')} modules")


def lens_evidence_recorded(src: str, kind: str, record: dict) -> Verdict:
    """A proof that brings back no structured evidence leaves a reader nothing to check."""
    ev = record.get("evidence") or {}
    if not ev:
        return Verdict("evidence-recorded", DEFER,
                       "no structured evidence recorded; observations are prose and cannot be "
                       "re-checked mechanically")
    return Verdict("evidence-recorded", APPROVE, f"{len(ev)} evidence field(s)")


def lens_independence(src: str, kind: str, record: dict) -> Verdict:
    """Always dissents. The gap it names is real and cannot be closed from inside."""
    return Verdict(
        "independence", DEFER,
        "the claim, the procedure and this panel share one author. No independent party has "
        "verified any of it. Closing this needs a review by someone who did not build the tool "
        "(#29)",
        independence="none",
    )


LENSES = (
    lens_can_fail,
    lens_adversarial_substance,
    lens_control_present,
    lens_asserts_on_computed_values,
    lens_witness_breadth,
    lens_evidence_recorded,
    lens_independence,
)


def judge(claim_id: str, fn, kind: str, record: dict) -> Panel:
    """Run every lens over one procedure and its proof record."""
    src = _source(fn)
    panel = Panel(claim_id)
    for lens in LENSES:
        try:
            panel.verdicts.append(lens(src, kind, record))
        except Exception as exc:  # noqa: BLE001 - a broken lens abstains, it does not block
            panel.verdicts.append(
                Verdict(getattr(lens, "__name__", "lens"), ABSTAIN, f"lens raised: {exc!r}"))
    return panel


def summarise(panels: list[Panel]) -> dict:
    total = sum(len(p.verdicts) for p in panels)
    deferred = [(p.claim_id, v) for p in panels for v in p.deferred]
    by_lens: dict[str, int] = {}
    for _cid, v in deferred:
        by_lens[v.lens] = by_lens.get(v.lens, 0) + 1
    return {
        "disclosure": PANEL_DISCLOSURE,
        "claims_judged": len(panels),
        "verdicts": total,
        "deferred_disapprovals": len(deferred),
        "by_lens": dict(sorted(by_lens.items(), key=lambda kv: -kv[1])),
        "detail": [{"claim": c, **v.to_dict()} for c, v in deferred],
    }
