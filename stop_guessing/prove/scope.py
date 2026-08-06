"""The scope ratchet — catch a claim being shrunk to make a verdict pass.

This exists because the tool failed to catch its own author. While closing an audit finding I
withdrew six `hook:` surfaces and five `plugin:`/`skill:`/`command:` surfaces from the claims,
because the proofs did not exercise them — and that is precisely what flipped `surface_validated`
to true. The claim-definition digest (R2-001) noticed the claims had *changed* and invalidated the
old proofs, which is correct and insufficient: it has no notion of DIRECTION. Broadening and
narrowing are the same event to it.

The failure mode is specific and it is the one this whole project is about:

    the party being measured quietly reduces what is asserted,
    the measurement improves,
    and every individual step looks like diligent housekeeping.

Nothing in the ledger connected those two facts, so nobody could see the trade. A human reader
caught it by asking whether the goal had moved.

**What this does.** Every claim's asserted scope — its declared surfaces and its AICM control
mappings — is recorded in the proof ledger. Scope is a RATCHET: it may grow freely, and it may
only shrink through an explicit, recorded retraction carrying a reason. An unrecorded shrink is a
finding, and `attest` reports scope retractions beside the verdict so a reader sees the claim got
smaller in the same breath as the number got better.

**This is an ISO 27037 alteration, not a new concept.** §5.4.1 requires that any unavoidable
alteration to evidence be recorded *with written justification*, and this record schema already
makes `alterations` a Tier-A required field so that `[]` is a positive assertion and a missing key
means nobody looked. Reducing what a claim asserts alters the evidence subject. I performed that
alteration by editing YAML, which recorded nothing — the tool mandated the mechanism and I went
around it. So a scope retraction is written as an alteration, through the same discipline every
other change to evidence already has to pass.

**What this deliberately does not do.** It does not forbid narrowing. Narrowing is often the
honest move — a claim that overreaches SHOULD be cut back, and this project has done that
correctly several times. What it forbids is narrowing *silently*. The retraction becomes evidence
rather than an absence, which is the same rule the record applies to `known_gaps`: an empty list is
an assertion, a missing key means nobody looked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

#: Fields whose contents ARE the claim's asserted scope. Shrinking any of them shrinks what is
#: being claimed, whatever the statement text says.
SCOPE_FIELDS = ("surface", "aicm")

SCOPE_OP = "claim.scope"
RETRACTION_OP = "claim.scope.retract"


@dataclass(frozen=True)
class Retraction:
    """One claim asserting less than it did, with whether anyone said why."""

    claim_id: str
    field: str
    removed: tuple[str, ...]
    justified: bool
    reason: str = ""

    def to_dict(self) -> dict:
        return {"claim": self.claim_id, "field": self.field, "removed": list(self.removed),
                "justified": self.justified, "reason": self.reason}

    def describe(self) -> str:
        what = f"{self.claim_id} no longer asserts {self.field}: {', '.join(self.removed)}"
        if self.justified:
            return f"{what} — retraction recorded: {self.reason}"
        return (f"{what} — NO RECORDED RETRACTION. Scope was reduced without a stated reason; "
                "if a verdict improved in the same change, that is the trade this check exists "
                "to surface.")


def scope_of(claim: dict) -> dict[str, list[str]]:
    """The claim's asserted scope, canonically."""
    return {f: sorted(str(x) for x in (claim.get(f) or [])) for f in SCOPE_FIELDS}


def scope_digest(claim: dict) -> str:
    from stop_guessing.artifacts.digest import bytes_digest

    canon = json.dumps(scope_of(claim), sort_keys=True, separators=(",", ":"))
    return bytes_digest(canon.encode("utf-8"))[:32]


def high_water(entries: list[dict], claim_id: str) -> dict[str, set[str]]:
    """The largest scope this claim has ever asserted, from the ledger.

    High-water rather than "the previous value" on purpose: shrinking across several commits, a
    surface at a time, would otherwise never register as a reduction. That is exactly how scope
    creep in the wrong direction happens — nobody removes ten things at once.
    """
    peak: dict[str, set[str]] = {f: set() for f in SCOPE_FIELDS}
    for e in entries:
        if e.get("op") != SCOPE_OP or e.get("claim") != claim_id:
            continue
        try:
            recorded = json.loads(e.get("detail") or "{}").get("scope") or {}
        except (ValueError, TypeError):
            continue
        for f in SCOPE_FIELDS:
            peak[f] |= {str(x) for x in (recorded.get(f) or [])}
    return peak


def justified_removals(entries: list[dict], claim_id: str) -> dict[str, dict[str, str]]:
    """Removals that carry an explicit recorded retraction, keyed field -> item -> reason."""
    out: dict[str, dict[str, str]] = {f: {} for f in SCOPE_FIELDS}
    for e in entries:
        if e.get("op") != RETRACTION_OP or e.get("claim") != claim_id:
            continue
        try:
            d = json.loads(e.get("detail") or "{}")
        except (ValueError, TypeError):
            continue
        field, reason = d.get("field"), d.get("reason") or ""
        if field not in out or not reason.strip():
            continue           # a retraction with no reason is not a justification
        for item in d.get("removed") or []:
            out[field][str(item)] = reason
    return out


def retractions(entries: list[dict], claim: dict) -> list[Retraction]:
    """Everything this claim used to assert and no longer does."""
    cid = claim["id"]
    peak = high_water(entries, cid)
    now = scope_of(claim)
    excused = justified_removals(entries, cid)

    out: list[Retraction] = []
    for field in SCOPE_FIELDS:
        gone = sorted(peak[field] - set(now.get(field) or []))
        if not gone:
            continue
        justified = [g for g in gone if g in excused[field]]
        unjustified = [g for g in gone if g not in excused[field]]
        if justified:
            out.append(Retraction(cid, field, tuple(justified), True,
                                  excused[field][justified[0]]))
        if unjustified:
            out.append(Retraction(cid, field, tuple(unjustified), False))
    return out


#: What the ratchet does NOT cover. This is a real limitation and it goes in `known_gaps` on every
#: scope record, because `known_gaps: []` is a positive assertion that nothing was skipped — and
#: writing `[]` here while knowing about this gap would be the same overclaim, one level up.
SCOPE_KNOWN_GAPS = (
    "the ratchet measures declared `surface` and `aicm` only: a claim whose STATEMENT TEXT is "
    "weakened while its surfaces stay constant is detected as a definition change (which "
    "invalidates its proofs) but is not identified as a REDUCTION, because comparing two prose "
    "assertions for strength is not mechanically decidable here",
)


def scope_event(claim: dict) -> dict:
    """The record that pins what this claim asserts, written on every proof run."""
    return {
        "op": SCOPE_OP,
        "claim": claim["id"],
        "detail": json.dumps({"scope": scope_of(claim), "digest": scope_digest(claim)},
                             sort_keys=True),
        "known_gaps": list(SCOPE_KNOWN_GAPS),
        "alterations": [],
    }


def retraction_event(claim_id: str, field: str, removed: list[str], reason: str) -> dict:
    """An explicit, reasoned reduction in what a claim asserts.

    Written by `stop-guessing claims retract`, never as a side effect of editing YAML. Making the
    operator name the reduction is the whole mechanism: a retraction anyone can perform silently
    is not a control.
    """
    if not (reason or "").strip():
        raise ValueError("a retraction without a reason is not a retraction")
    return {
        "op": RETRACTION_OP,
        "claim": claim_id,
        "severity": "warning",
        "detail": json.dumps({"field": field, "removed": sorted(removed), "reason": reason},
                             sort_keys=True),
        "known_gaps": [f"{claim_id} asserts less than it did: {', '.join(sorted(removed))}"],
        # ISO/IEC 27037 §5.4.1: the alteration, what it was, and the written justification. This
        # is the field the schema has always required and that editing YAML silently bypassed.
        "alterations": [{
            "what": f"claim.{claim_id}.{field}",
            "kind": "scope-retraction",
            "justification": reason,
            "authorized_by": "operator via `stop-guessing claims retract`",
            "removed": sorted(removed),
            "reversible": True,
        }],
    }
