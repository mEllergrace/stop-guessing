"""A Cedar-shaped policy decision point.

Cedar's semantics, kept exactly:

- **Deny by default.** No matching `permit` means no permission.
- **`forbid` overrides `permit`**, unconditionally and regardless of order. A rule that can be
  outvoted by adding another rule is not a control.
- Policies are `(effect, principal, action, resource, when)` over a typed `context`.

Cedar's *implementation* is not kept, deliberately — see `stop_guessing/policy/__init__.py`.

The `ask` effect is the one no existing hook in this estate produces. Claude Code's
`hookSpecificOutput.permissionDecision` has supported `ask` all along and nothing uses it;
everything writes to stdout and exits 2. `ask` is what "the agentic decides how to respond to a
request for data" actually looks like at the protocol level — not a refusal, a redirection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EFFECTS = ("forbid", "ask", "permit")
PRECEDENCE = {"forbid": 3, "ask": 2, "permit": 1}


@dataclass(frozen=True)
class Policy:
    id: str
    effect: str
    when: dict
    reason: str
    actions: tuple[str, ...] = ()
    postures: tuple[str, ...] = ()
    guidance: str = ""

    def applies_to(self, action: str, posture: str) -> bool:
        if self.actions and action not in self.actions:
            return False
        return not (self.postures and posture not in self.postures)


@dataclass
class Decision:
    outcome: str
    determining_policy: str
    reason: str
    evaluated: list[str] = field(default_factory=list)
    guidance: str = ""
    counterfactual: str = ""

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "determining_policy": self.determining_policy,
            "reason": self.reason,
            "policies_evaluated": list(self.evaluated),
            "guidance": self.guidance,
            "counterfactual": self.counterfactual,
        }


# ── condition language ───────────────────────────────────────────────────────

def _resolve(context: dict, path: str) -> Any:
    cur: Any = context
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _test(op: str, actual: Any, expected: Any) -> bool:
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "gte":
        return actual is not None and actual >= expected
    if op == "gt":
        return actual is not None and actual > expected
    if op == "lte":
        return actual is not None and actual <= expected
    if op == "lt":
        return actual is not None and actual < expected
    if op == "in":
        return actual in (expected or [])
    if op == "contains":
        return bool(actual) and expected in actual
    if op == "contains_any":
        return bool(actual) and bool(set(actual) & set(expected or []))
    if op == "matches":
        return bool(actual) and bool(re.search(expected, str(actual)))
    if op == "is_true":
        return actual is True
    if op == "is_false":
        return actual is not True
    raise ValueError(f"unknown condition operator {op!r}")


def evaluate_when(when: dict, context: dict) -> bool:
    """All conditions must hold. ``when: {}`` means unconditional."""
    for path, cond in when.items():
        if not isinstance(cond, dict):
            cond = {"eq": cond}
        for op, expected in cond.items():
            if not _test(op, _resolve(context, path), expected):
                return False
    return True


# ── the engine ───────────────────────────────────────────────────────────────


class PolicySet:
    def __init__(self, policies: list[Policy], digest: str, schema_digest: str = ""):
        self.policies = policies
        self.digest = digest
        self.schema_digest = schema_digest

    def evaluate(self, action: str, context: dict) -> Decision:
        posture = context.get("posture", "steer")
        evaluated, matches = [], []
        for p in self.policies:
            if not p.applies_to(action, posture):
                continue
            evaluated.append(p.id)
            if evaluate_when(p.when, context):
                matches.append(p)

        if not matches:
            return Decision(
                "deny", "default#deny-by-default",
                "no policy permitted this action — deny by default",
                evaluated,
            )

        # forbid > ask > permit, regardless of declaration order.
        winner = max(matches, key=lambda p: PRECEDENCE[p.effect])
        outcome = {"forbid": "deny", "ask": "ask", "permit": "allow"}[winner.effect]
        overridden = [p.id for p in matches
                      if PRECEDENCE[p.effect] < PRECEDENCE[winner.effect]]
        counterfactual = (
            f"would have been {', '.join(overridden)} but {winner.effect} overrides"
            if overridden else ""
        )
        return Decision(outcome, winner.id, winner.reason, evaluated,
                        winner.guidance, counterfactual)


def load(directory: str | Path) -> PolicySet:
    import yaml

    from stop_guessing.artifacts.digest import bytes_digest

    d = Path(directory)
    policies: list[Policy] = []
    blobs: list[bytes] = []
    for path in sorted(d.glob("*.yaml")):
        raw = path.read_bytes()
        blobs.append(raw)
        doc = yaml.safe_load(raw.decode()) or {}
        stem = path.stem
        for entry in doc.get("policies", []):
            effect = entry["effect"]
            if effect not in EFFECTS:
                raise ValueError(f"{path}: unknown effect {effect!r}")
            policies.append(Policy(
                id=f"{stem}#{entry['id']}",
                effect=effect,
                when=entry.get("when", {}),
                reason=entry.get("reason", ""),
                actions=tuple(entry.get("actions", ())),
                postures=tuple(entry.get("postures", ())),
                guidance=entry.get("guidance", ""),
            ))
    return PolicySet(policies, bytes_digest(b"".join(blobs)))


def to_cedar(policy_set: PolicySet) -> str:
    """Emit Cedar for `cedar validate`.

    Fixes #28 as far as it can be fixed, and states the remainder instead of implying it away. The
    export previously dropped action and posture restrictions and rendered unsupported operators as
    `/* op */ true`, so a rule that fires only under `bar` on `artifact.egress` exported as
    UNCONDITIONAL — and validating that established nothing about the runtime.

    Now scope is encoded as real conditions, every operator has an explicit rendering, and anything
    still inexpressible becomes `false` rather than `true`: an unrepresentable condition must make
    its rule inert, never universal.

    **`ask` stays inexpressible.** Cedar has permit and forbid and no third answer. Ask policies
    export as `forbid`, marked individually and counted in the header. So `cedar validate` proves
    this file is well-formed and that its permit/forbid subset is coherent. It does not prove the
    runtime engine and this file decide alike, and nothing here says otherwise.
    """
    asks = [p.id for p in policy_set.policies if p.effect == "ask"]
    lines = [
        "// Generated by `stop-guessing policy export --cedar`. Do not edit.",
        "// Policy set digest: " + policy_set.digest,
        "//",
        "// SCOPE: `cedar validate` on this file proves it is well-formed Cedar and that its",
        "// permit/forbid subset is coherent. It does NOT prove the runtime engine decides the",
        "// same way, because Cedar has no `ask` effect and the runtime does (#28).",
        "// ask policies exported as forbid (" + str(len(asks)) + "): "
        + (", ".join(asks) or "none"),
        "",
    ]
    for p in policy_set.policies:
        conds = []
        # Scope, which the old export dropped entirely.
        if p.postures:
            conds.append("(" + " || ".join(
                'context.posture == "' + x + '"' for x in p.postures) + ")")
        if p.actions:
            conds.append("(" + " || ".join(
                'context.op == "' + x + '"' for x in p.actions) + ")")
        for path, cond in p.when.items():
            if not isinstance(cond, dict):
                cond = {"eq": cond}
            for op, expected in cond.items():
                ref = "context." + path
                if op == "eq":
                    conds.append(ref + " == " + _cedar_lit(expected))
                elif op in ("gte", "gt", "lte", "lt"):
                    sym = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}[op]
                    conds.append(f"{ref} {sym} {expected}")
                elif op == "is_true":
                    conds.append(ref)
                elif op == "is_false":
                    conds.append(f"!{ref}")
                elif op == "ne":
                    conds.append(ref + " != " + _cedar_lit(expected))
                elif op == "contains":
                    conds.append(ref + ".contains(" + _cedar_lit(expected) + ")")
                elif op == "contains_any":
                    conds.append("(" + " || ".join(
                        ref + ".contains(" + _cedar_lit(e) + ")" for e in expected) + ")")
                elif op == "in":
                    conds.append("(" + " || ".join(
                        ref + " == " + _cedar_lit(e) for e in expected) + ")")
                else:
                    # INERT, not universal. `true` here made an unrepresentable rule always fire.
                    conds.append("/* unrepresentable: " + op + " */ false")
        effect = "forbid" if p.effect in ("forbid", "ask") else "permit"
        note = ("  // runtime effect is ASK; Cedar has no ask, so this is forbid here (#28)"
                if p.effect == "ask" else "")
        guard = ("\nwhen { " + " && ".join(conds) + " }") if conds else ""
        lines.append(f"// {p.id}: {p.reason}{note}")
        lines.append(f"{effect} (principal, action, resource){guard};")
        lines.append("")
    return "\n".join(lines)


def _cedar_lit(v) -> str:
    """A Cedar literal. Strings are quoted and escaped rather than run through repr(), which
    emits Python single-quoted strings that Cedar does not accept."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + s + '"'
