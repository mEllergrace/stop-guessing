"""Did the proof procedure actually execute anything?

**Fixes #31.** Mutation testing showed all 21 procedures could be replaced with
`lambda: ProofResult(True)` and every claim was still reported PROVEN. The system recorded what a
procedure *said* and had no notion of whether it *did* anything. `procedure_digest` catches a
procedure changed after the fact; it says nothing about one that never did the work.

So the procedure is instrumented while it runs, and the set of `stop_guessing.*` modules it
actually entered is recorded in the proof. A vacuous procedure enters none.

Two gates come out of this:

- **Non-triviality.** A proof whose witness is empty, or barely there, is not a proof. The floor is
  deliberately low — it exists to catch "did nothing", not to grade thoroughness.
- **`must_touch`.** A claim may name the modules a genuine proof has to enter. A proof for the
  ledger claim that never executed `stop_guessing.ledger.chain` is about something else.

`sys.setprofile` rather than `settrace`: call events only, so the overhead is per-call rather than
per-line, and a proof that replays 73 hook payloads does not become unusably slow. It is also
per-thread — noted as a known limitation rather than papered over.
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field

PACKAGE = "stop_guessing"

#: Modules that every procedure touches simply by being called through the runner. Excluded so
#: they cannot be mistaken for evidence that the procedure did its own work.
AMBIENT = frozenset({
    "stop_guessing.prove.witness",
    "stop_guessing.prove.registry",
    "stop_guessing.prove.runner",
    "stop_guessing.version",
})

#: The floor for "this procedure did something". It separates zero from non-zero and nothing more.
#:
#: MIN_MODULES was briefly 2, which was wrong: a focused proof of one module is perfectly
#: legitimate, and punishing it would push procedures to touch extra code for the sake of the
#: gate — optimising the measure instead of the thing. One module is the honest floor, because a
#: vacuous procedure enters none. Adequacy is `must_touch`'s job, not the floor's.
MIN_MODULES = 1
MIN_CALLS = 25


@dataclass
class Witness:
    modules: set[str] = field(default_factory=set)
    calls: int = 0
    #: Set when instrumentation could not run at all, so an absent witness is never read as a
    #: clean one.
    unavailable: str | None = None

    def to_dict(self) -> dict:
        return {
            "modules": sorted(self.modules),
            "module_count": len(self.modules),
            "calls": self.calls,
            "unavailable": self.unavailable,
        }

    @property
    def trivial(self) -> bool:
        return len(self.modules) < MIN_MODULES or self.calls < MIN_CALLS


def _module_of(frame) -> str | None:
    name = frame.f_globals.get("__name__")
    if not isinstance(name, str) or not name.startswith(PACKAGE):
        return None
    return name


class _Profiler:
    """Records which package modules were entered, and how many calls happened inside them."""

    def __init__(self, w: Witness):
        self.w = w

    def __call__(self, frame, event, arg):
        if event not in ("call", "c_call"):
            return
        mod = _module_of(frame)
        if mod is None or mod in AMBIENT:
            return
        self.w.modules.add(mod)
        self.w.calls += 1


def observe(fn):
    """Run ``fn`` under instrumentation. Returns ``(result, Witness)``.

    Instrumentation failure is recorded, never swallowed: a witness that could not be taken must
    not be indistinguishable from a witness that came back empty.
    """
    w = Witness()
    prof = _Profiler(w)
    previous = sys.getprofile()
    try:
        sys.setprofile(prof)
        threading.setprofile(prof)
    except Exception as exc:  # noqa: BLE001 - platform or debugger conflict
        w.unavailable = f"{type(exc).__name__}: {exc}"
        return fn(), w
    try:
        result = fn()
    finally:
        sys.setprofile(previous)
        threading.setprofile(None)
    return result, w


def check(
    witness: dict | None,
    must_touch: list[str] | None = None,
    *,
    mode: str = "in-process",
    evidence: dict | None = None,
) -> list[str]:
    """Findings that disqualify a proof. Empty list means the witness is acceptable.

    A proof recorded before witnesses existed has no witness at all. That is reported as a finding
    rather than accepted, because "we did not look" must not read as "it was fine" — the same rule
    the record schema applies to `known_gaps`.
    """
    if witness is None:
        return ["no execution witness — the proof predates witnessing and cannot be trusted "
                "to have executed anything (#31); re-run `stop-guessing prove`"]
    if witness.get("unavailable"):
        return [f"execution witness unavailable ({witness['unavailable']}) — cannot confirm the "
                "procedure executed anything"]

    findings = []
    modules = set(witness.get("modules") or [])
    calls = witness.get("calls") or 0

    if mode == "subprocess":
        # A proof that drives the packaged CLI or the real hook in a child process legitimately
        # executes almost nothing in-process, so in-process `must_touch` cannot apply. The
        # substitute signal is that it came back with evidence: a subprocess proof that recorded
        # nothing observed nothing.
        if not evidence:
            findings.append(
                "subprocess proof recorded no evidence — a proof that drives a child process and "
                "brings back nothing has observed nothing (#31)"
            )
        return findings
    if len(modules) < MIN_MODULES or calls < MIN_CALLS:
        findings.append(
            f"vacuous proof: the procedure entered {len(modules)} package module(s) with {calls} "
            f"call(s), below the floor of {MIN_MODULES}/{MIN_CALLS}. A procedure that executes "
            "nothing and returns passed=True is not a proof (#31)"
        )
    for required in must_touch or []:
        if not any(m == required or m.startswith(required + ".") for m in modules):
            findings.append(
                f"the procedure never entered {required}, which this claim is about — "
                "the proof is about something else"
            )
    return findings
